from .data_structures import Proposal, Welcome, GroupContext, AddProposal, UpdateProposal, RemoveProposal, Sender, Signature, Commit, MLSVersion, CipherSuite, GroupInfo
from .key_packages import KeyPackage, LeafNode
from .messages import (
    MLSPlaintext,
    MLSCiphertext,
    ContentType,
    sign_authenticated_content,
    attach_membership_tag,
    verify_plaintext,
    protect_content_application,
    unprotect_content_application,
)
from .ratchet_tree import RatchetTree
from .key_schedule import KeySchedule
from .secret_tree import SecretTree
from ..extensions.extensions import Extension, ExtensionType, serialize_extensions, deserialize_extensions
from .validations import validate_proposals_client_rules
from ..crypto.crypto_provider import CryptoProvider


class MLSGroup:
    def __init__(self, group_id: bytes, crypto_provider: CryptoProvider, own_leaf_index: int):
        self._group_id = group_id
        self._crypto_provider = crypto_provider
        self._ratchet_tree = RatchetTree(crypto_provider)
        self._group_context: GroupContext | None = None
        self._key_schedule: KeySchedule | None = None
        self._secret_tree: SecretTree | None = None
        self._interim_transcript_hash: bytes | None = None
        self._confirmed_transcript_hash: bytes | None = None
        self._pending_proposals: list[Proposal] = []
        self._own_leaf_index = own_leaf_index

    @classmethod
    def create(cls, group_id: bytes, key_package: KeyPackage, crypto_provider: CryptoProvider) -> "MLSGroup":
        group = cls(group_id, crypto_provider, 0)
        group._ratchet_tree.add_leaf(key_package)
        # This is a simplification. The initial secrets and group context would be derived differently.
        init_secret = crypto_provider.kdf_extract(b"", b"")
        commit_secret = crypto_provider.kdf_extract(b"", b"")
        group._group_context = GroupContext(group_id, 0, group._ratchet_tree.calculate_tree_hash(), b"")
        group._key_schedule = KeySchedule(init_secret, commit_secret, group._group_context, None, crypto_provider)
        group._secret_tree = SecretTree(group._key_schedule.application_secret, group._key_schedule.handshake_secret, crypto_provider)
        return group

    @classmethod
    def from_welcome(cls, welcome: Welcome, hpke_private_key: bytes, crypto_provider: CryptoProvider) -> "MLSGroup":
        """
        Minimal welcome processing:
        - Decrypt one EncryptedGroupSecret using provided HPKE private key
        - Decrypt GroupInfo using the recovered secret
        - Initialize group context and key schedule
        """
        # Try each secret until one opens
        epoch_secret = None
        for blob in welcome.secrets:
            try:
                # Our Welcome encodes enc || ct where enc length depends on KEM.
                # We cannot split by fixed size, so assume enc=first half? Not reliable.
                # For this placeholder, we expect enc||ct where enc is KEM pk size for DH suites.
                # If that fails, skip.
                try:
                    enc_len = crypto_provider.kem_pk_size()
                    enc, ct = blob[:enc_len], blob[enc_len:]
                except NotImplementedError:
                    # DER-encoded EC public key in KEMs without fixed size: cannot split reliably.
                    # Skip in placeholder.
                    continue
                epoch_secret = crypto_provider.hpke_open(hpke_private_key, enc, b"welcome secret", b"", ct)
                break
            except Exception:
                continue
        if epoch_secret is None:
            raise ValueError("Unable to open any EncryptedGroupSecret with provided HPKE private key")

        # Decrypt GroupInfo
        nonce = b"\x00" * crypto_provider.aead_nonce_size()
        gi_bytes = crypto_provider.aead_decrypt(epoch_secret, nonce, welcome.encrypted_group_info, b"")
        from .data_structures import GroupInfo as GroupInfoStruct
        gi = GroupInfoStruct.deserialize(gi_bytes)

        group = cls(gi.group_context.group_id, crypto_provider, -1)
        group._group_context = gi.group_context
        # Initialize key schedule with recovered secret (commit_secret is unknown; reuse as both)
        group._key_schedule = KeySchedule(epoch_secret, epoch_secret, gi.group_context, None, crypto_provider)
        group._secret_tree = SecretTree(group._key_schedule.application_secret, group._key_schedule.handshake_secret, crypto_provider)
        # Ratchet tree via GroupInfo extension (if present)
        if gi.extensions:
            try:
                exts = deserialize_extensions(gi.extensions)
                for e in exts:
                    if e.ext_type == ExtensionType.RATCHET_TREE:
                        group._ratchet_tree.load_tree_from_welcome_bytes(e.data)
                        break
            except Exception:
                # If extension parsing fails, proceed without tree
                pass
        return group

    # --- Additional lifecycle APIs (placeholders) ---
    def external_commit(self):
        raise NotImplementedError("external_commit not implemented yet")

    def external_join(self):
        raise NotImplementedError("external_join not implemented yet")

    def reinit_group(self):
        raise NotImplementedError("reinit_group not implemented yet")

    def create_add_proposal(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        proposal = AddProposal(key_package.serialize())
        proposal_bytes = proposal.serialize()
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal_bytes,
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    def create_update_proposal(self, leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext:
        proposal = UpdateProposal(leaf_node.serialize())
        proposal_bytes = proposal.serialize()
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal_bytes,
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    def create_remove_proposal(self, removed_index: int, signing_key: bytes) -> MLSPlaintext:
        proposal = RemoveProposal(removed_index)
        proposal_bytes = proposal.serialize()
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal_bytes,
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    def process_proposal(self, message: MLSPlaintext, sender: Sender) -> None:
        sender_leaf_node = self._ratchet_tree.get_node(sender.sender * 2).leaf_node
        if not sender_leaf_node:
            raise ValueError(f"No leaf node found for sender index {sender.sender}")

        # Verify MLSPlaintext (signature and membership tag)
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        proposal = Proposal.deserialize(message.auth_content.tbs.framed_content.content)
        self._pending_proposals.append(proposal)

    def create_commit(self, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        # This is a simplification. It handles a self-update and pending proposals.
        removes = [p.removed for p in self._pending_proposals if isinstance(p, RemoveProposal)]
        adds_kps = [KeyPackage.deserialize(p.key_package) for p in self._pending_proposals if isinstance(p, AddProposal)]
        # Basic validations
        validate_proposals_client_rules(self._pending_proposals, self._ratchet_tree.n_leaves)
        # Apply removes and adds before generating the update path (MVP ordering)
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except Exception:
                continue
        for kp in adds_kps:
            try:
                self._ratchet_tree.add_leaf(kp)
            except Exception:
                continue

        # Create an update path for the committer (ourselves)
        own_node = self._ratchet_tree.get_node(self._own_leaf_index * 2)
        # In a real update, this leaf node would be regenerated with new credentials
        new_leaf_node = own_node.leaf_node
        update_path, commit_secret = self._ratchet_tree.create_update_path(self._own_leaf_index, new_leaf_node)

        # Construct and sign the commit
        temp_commit = Commit(
            path=update_path,
            removes=removes,
            adds=[kp.serialize() for kp in adds_kps],
            signature=Signature(b"")  # Empty signature for serialization
        )
        commit_bytes_for_signing = temp_commit.serialize()
        signature_value = self._crypto_provider.sign(signing_key, commit_bytes_for_signing)
        commit = Commit(temp_commit.path, temp_commit.removes, temp_commit.adds, Signature(signature_value))

        # Update transcript hashes (placeholder chaining)
        prev_i = self._interim_transcript_hash or b""
        interim = self._crypto_provider.kdf_extract(prev_i, commit_bytes_for_signing)

        # Advance epoch and derive new key schedule
        new_epoch = self._group_context.epoch + 1
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        new_group_context = GroupContext(self._group_id, new_epoch, tree_hash, b"")  # filled after confirm tag

        self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, None, self._crypto_provider)
        self._secret_tree = SecretTree(self._key_schedule.application_secret, self._key_schedule.handshake_secret, self._crypto_provider)
        self._group_context = new_group_context
        self._pending_proposals = []

        # Compute confirmation tag (placeholder: HMAC over commit bytes) and update confirmed transcript hash
        commit_bytes = commit.serialize()
        confirm_tag = self._crypto_provider.hmac_sign(self._key_schedule.confirmation_key, commit_bytes)[:16]
        confirmed = self._crypto_provider.kdf_extract(interim, confirm_tag)
        self._interim_transcript_hash = interim
        self._confirmed_transcript_hash = confirmed
        # update group context with confirmed hash
        self._group_context = GroupContext(self._group_id, new_epoch, tree_hash, confirmed)

        # Construct Welcome messages for any added members (placeholder encoding)
        welcomes: list[Welcome] = []
        if adds_kps:
            # Include ratchet_tree extension for new members
            rt_bytes = self._ratchet_tree.serialize_tree_for_welcome()
            ext_bytes = serialize_extensions([Extension(ExtensionType.RATCHET_TREE, rt_bytes)])
            group_info = GroupInfo(new_group_context, Signature(b""), ext_bytes)
            enc_group_info = self._crypto_provider.aead_encrypt(
                self._key_schedule.encryption_secret, b"\x00" * self._crypto_provider.aead_nonce_size(), group_info.serialize(), b""
            )
            secrets: list[bytes] = []
            for kp in adds_kps:
                pk = kp.leaf_node.encryption_key
                enc, ct = self._crypto_provider.hpke_seal(pk, b"welcome secret", b"", self._key_schedule.epoch_secret)
                secrets.append(enc + ct)
            welcome = Welcome(MLSVersion.MLS10, CipherSuite(self._crypto_provider.active_ciphersuite.kem, self._crypto_provider.active_ciphersuite.kdf, self._crypto_provider.active_ciphersuite.aead), secrets, enc_group_info)
            welcomes.append(welcome)

        # Wrap commit in MLSPlaintext (handshake). Membership tag acts as MVP confirmation.
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content_type=ContentType.COMMIT,
            content=commit.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
        )
        pt = attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)
        return pt, welcomes

    def process_commit(self, message: MLSPlaintext, sender_index: int) -> None:
        # Verify plaintext container
        sender_leaf_node = self._ratchet_tree.get_node(sender_index * 2).leaf_node
        if not sender_leaf_node:
            raise ValueError(f"No leaf node for committer index {sender_index}")
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)

        # Verify commit inner signature
        temp_commit = Commit(commit.path, commit.removes, commit.adds, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()
        self._crypto_provider.verify(sender_leaf_node.signature_key, commit_bytes_for_signing, commit.signature.value)

        # Apply changes and derive new key schedule
        if commit.path:
            # Apply removals and additions before merging path (MVP)
            for idx in sorted(commit.removes, reverse=True):
                try:
                    self._ratchet_tree.remove_leaf(idx)
                except Exception:
                    continue
            for kp_bytes in commit.adds:
                try:
                    self._ratchet_tree.add_leaf(KeyPackage.deserialize(kp_bytes))
                except Exception:
                    continue
            commit_secret = self._ratchet_tree.merge_update_path(commit.path, sender_index)

            # Advance epoch
            new_epoch = self._group_context.epoch + 1
            tree_hash = self._ratchet_tree.calculate_tree_hash()
            # Update transcript hashes
            prev_i = self._interim_transcript_hash or b""
            interim = self._crypto_provider.kdf_extract(prev_i, commit_bytes_for_signing)
            # Derive confirmed hash using placeholder confirmation recomputation
            commit_bytes_full = commit.serialize()
            confirm_tag = self._crypto_provider.hmac_sign(self._key_schedule.confirmation_key, commit_bytes_full)[:16]
            confirmed = self._crypto_provider.kdf_extract(interim, confirm_tag)
            new_group_context = GroupContext(self._group_id, new_epoch, tree_hash, confirmed)

            self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, None, self._crypto_provider)
            self._secret_tree = SecretTree(self._key_schedule.application_secret, self._key_schedule.handshake_secret, self._crypto_provider)
            self._group_context = new_group_context
            self._interim_transcript_hash = interim
            self._confirmed_transcript_hash = confirmed
        else:
            raise NotImplementedError("Processing commits without a path is not supported yet.")

    def protect(self, app_data: bytes) -> MLSCiphertext:
        return protect_content_application(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content=app_data,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )

    def unprotect(self, message: MLSCiphertext) -> tuple[int, bytes]:
        return unprotect_content_application(
            message,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )

    def get_epoch(self) -> int:
        return self._group_context.epoch

    def get_group_id(self) -> bytes:
        return self._group_id

    # --- Persistence (minimal) ---
    def to_bytes(self) -> bytes:
        from .data_structures import serialize_bytes
        if not self._group_context or not self._key_schedule:
            raise ValueError("group not initialized")
        data = b""
        data += serialize_bytes(self._group_id)
        data += serialize_bytes(self._group_context.serialize())
        data += serialize_bytes(self._key_schedule.epoch_secret)
        data += serialize_bytes(self._key_schedule.handshake_secret)
        data += serialize_bytes(self._key_schedule.application_secret)
        data += serialize_bytes(self._confirmed_transcript_hash or b"")
        data += serialize_bytes(self._interim_transcript_hash or b"")
        data += serialize_bytes(self._own_leaf_index.to_bytes(4, "big"))
        return data

    @classmethod
    def from_bytes(cls, data: bytes, crypto_provider: CryptoProvider) -> "MLSGroup":
        from .data_structures import deserialize_bytes, GroupContext
        gid, rest = deserialize_bytes(data)
        gc_bytes, rest = deserialize_bytes(rest)
        epoch_secret, rest = deserialize_bytes(rest)
        hs, rest = deserialize_bytes(rest)
        app, rest = deserialize_bytes(rest)
        cth, rest = deserialize_bytes(rest)
        ith, rest = deserialize_bytes(rest)
        own_idx_bytes, rest = deserialize_bytes(rest)
        own_idx = int.from_bytes(own_idx_bytes, "big")

        group = cls(gid, crypto_provider, own_idx)
        gc = GroupContext.deserialize(gc_bytes)
        group._group_context = gc
        # Recreate key schedule anchored at epoch_secret
        ks = KeySchedule(epoch_secret, epoch_secret, gc, None, crypto_provider)
        group._key_schedule = ks
        group._confirmed_transcript_hash = cth if cth else None
        group._interim_transcript_hash = ith if ith else None
        return group

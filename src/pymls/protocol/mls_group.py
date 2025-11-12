"""
Core group state machine for MLS.

Rationale:
- Implements RFC 9420 §8 (Group operations), including commit processing,
  external commit (MVP), and application protection (§9).
"""
from .data_structures import Proposal, Welcome, GroupContext, AddProposal, UpdateProposal, RemoveProposal, PreSharedKeyProposal, ExternalInitProposal, ReInitProposal, Sender, Signature, Commit, MLSVersion, CipherSuite, GroupInfo, EncryptedGroupSecrets
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
from .transcripts import TranscriptState
from ..extensions.extensions import Extension, ExtensionType, serialize_extensions, deserialize_extensions
from .validations import validate_proposals_client_rules, validate_commit_matches_referenced_proposals
from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import (
    PyMLSError,
    CommitValidationError,
    InvalidSignatureError,
    ConfigurationError,
)


class MLSGroup:
    """Core MLS group state machine and message processing.

    This class encapsulates the ratchet tree, key schedule, transcript hashes,
    pending proposals, and helpers for producing and consuming MLS handshake
    and application messages. The implementation targets RFC 9420 semantics
    with some MVP simplifications noted in method docs.
    """
    def __init__(self, group_id: bytes, crypto_provider: CryptoProvider, own_leaf_index: int):
        """Initialize a new MLSGroup wrapper around cryptographic providers.

        Parameters
        - group_id: Application-chosen identifier for the group.
        - crypto_provider: Active CryptoProvider instance.
        - own_leaf_index: Local member's leaf index in the group ratchet tree,
          or -1 for groups created from a Welcome before inserting self.
        """
        self._group_id = group_id
        self._crypto_provider = crypto_provider
        self._ratchet_tree = RatchetTree(crypto_provider)
        self._group_context: GroupContext | None = None
        self._key_schedule: KeySchedule | None = None
        self._secret_tree: SecretTree | None = None
        self._interim_transcript_hash: bytes | None = None
        self._confirmed_transcript_hash: bytes | None = None
        self._pending_proposals: list[Proposal] = []
        self._proposal_cache: dict[bytes, Proposal] = {}
        self._own_leaf_index = own_leaf_index
        self._external_private_key: bytes | None = None
        self._external_public_key: bytes | None = None
        self._trust_roots: list[bytes] = []
        self._strict_psk_binders: bool = True
        self._x509_policy = None

    @classmethod
    def create(cls, group_id: bytes, key_package: KeyPackage, crypto_provider: CryptoProvider) -> "MLSGroup":
        """Create a new group with an initial member represented by key_package.

        Parameters
        - group_id: New group identifier.
        - key_package: Joiner's KeyPackage to insert as the first leaf.
        - crypto_provider: Active CryptoProvider.

        Returns
        - Initialized MLSGroup instance with epoch 0 and derived secrets.

        Notes
        - This is an MVP simplification: initial secrets are derived as neutral
          extracts rather than following the full RFC path.
        """
        group = cls(group_id, crypto_provider, 0)
        group._ratchet_tree.add_leaf(key_package)
        # This is a simplification. The initial secrets and group context would be derived differently.
        init_secret = crypto_provider.kdf_extract(b"", b"")
        commit_secret = crypto_provider.kdf_extract(b"", b"")
        group._group_context = GroupContext(group_id, 0, group._ratchet_tree.calculate_tree_hash(), b"")
        group._key_schedule = KeySchedule(init_secret, commit_secret, group._group_context, None, crypto_provider)
        group._secret_tree = SecretTree(
            group._key_schedule.application_secret,
            group._key_schedule.handshake_secret,
            crypto_provider,
            n_leaves=group._ratchet_tree.n_leaves,
        )
        # Generate external HPKE key for ExternalPub extension (MVP)
        ext_sk, ext_pk = crypto_provider.generate_key_pair()
        group._external_private_key = ext_sk
        group._external_public_key = ext_pk
        return group

    @classmethod
    def from_welcome(cls, welcome: Welcome, hpke_private_key: bytes, crypto_provider: CryptoProvider) -> "MLSGroup":
        """Join a group using a Welcome message (MVP flow).

        Steps
        - Attempt to open each EncryptedGroupSecrets with the provided HPKE private key.
        - Decrypt GroupInfo using the recovered epoch secret.
        - Optionally verify GroupInfo using external or tree-provided public keys.
        - Initialize GroupContext, KeySchedule, SecretTree, and optional ratchet tree.

        Parameters
        - welcome: Welcome structure received out-of-band.
        - hpke_private_key: Private key for HPKE to recover the epoch secret.
        - crypto_provider: Active CryptoProvider.

        Returns
        - MLSGroup instance initialized from the Welcome.

        Raises
        - CommitValidationError: If no EncryptedGroupSecrets can be opened.
        - InvalidSignatureError: If a present GroupInfo signature fails validation.
        """
        # Try each secret until one opens
        epoch_secret = None
        for egs in welcome.secrets:
            try:
                epoch_secret = crypto_provider.hpke_open(hpke_private_key, egs.kem_output, b"welcome secret", b"", egs.ciphertext)
                break
            except Exception:
                continue
        if epoch_secret is None:
            raise CommitValidationError("Unable to open any EncryptedGroupSecret with provided HPKE private key")

        # Decrypt GroupInfo
        nonce = b"\x00" * crypto_provider.aead_nonce_size()
        gi_bytes = crypto_provider.aead_decrypt(epoch_secret, nonce, welcome.encrypted_group_info, b"")
        from .data_structures import GroupInfo as GroupInfoStruct
        gi = GroupInfoStruct.deserialize(gi_bytes)
        # Verify GroupInfo signature: try EXTERNAL_PUB first; otherwise, try any leaf signature key from ratchet_tree extension
        verifier_keys: list[bytes] = []
        ext_external_pub: bytes | None = None
        ext_tree_bytes: bytes | None = None
        if gi.extensions:
            try:
                exts = deserialize_extensions(gi.extensions)
                for e in exts:
                    if e.ext_type == ExtensionType.EXTERNAL_PUB:
                        ext_external_pub = e.data
                    elif e.ext_type == ExtensionType.RATCHET_TREE:
                        ext_tree_bytes = e.data
            except Exception:
                # If extension parsing fails, continue and attempt join optimistically
                pass
        if ext_external_pub:
            verifier_keys.append(ext_external_pub)
        # If ratchet tree is present, load and collect leaf signature keys
        if ext_tree_bytes:
            try:
                tmp_tree = RatchetTree(crypto_provider)
                tmp_tree.load_tree_from_welcome_bytes(ext_tree_bytes)
                for leaf in range(tmp_tree.n_leaves):
                    node = tmp_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.signature_key:
                        verifier_keys.append(node.leaf_node.signature_key)
            except Exception:
                pass
        # Attempt verification with any candidate key if available
        if verifier_keys:
            verified = False
            tbs = gi.tbs_serialize()
            for vk in verifier_keys:
                try:
                    crypto_provider.verify(vk, tbs, gi.signature.value)
                    verified = True
                    break
                except Exception:
                    continue
            if not verified:
                raise InvalidSignatureError("invalid GroupInfo signature")

        group = cls(gi.group_context.group_id, crypto_provider, -1)
        group._group_context = gi.group_context
        # Initialize key schedule with recovered secret (commit_secret is unknown; reuse as both)
        group._key_schedule = KeySchedule(epoch_secret, epoch_secret, gi.group_context, None, crypto_provider)
        group._secret_tree = SecretTree(
            group._key_schedule.application_secret,
            group._key_schedule.handshake_secret,
            crypto_provider,
            n_leaves=1,  # will be updated if/when ratchet tree extension is loaded
        )
        # Ratchet tree via GroupInfo extension (if present)
        if gi.extensions:
            try:
                exts = deserialize_extensions(gi.extensions)
                for e in exts:
                    if e.ext_type == ExtensionType.RATCHET_TREE:
                        group._ratchet_tree.load_tree_from_welcome_bytes(e.data)
                    elif e.ext_type == ExtensionType.EXTERNAL_PUB:
                        group._external_public_key = e.data
            except Exception:
                # If extension parsing fails, proceed without tree
                pass
        return group

    # --- Additional lifecycle APIs (placeholders) ---
    def set_trust_roots(self, roots_pem: list[bytes]) -> None:
        """Configure X.509 trust anchors for credential validation."""
        self._trust_roots = roots_pem

    def set_strict_psk_binders(self, enforce: bool) -> None:
        """Toggle strict PSK binder enforcement (default True).

        If enabled, commits that reference PSK proposals must carry a valid
        PSK binder in authenticated_data.
        """
        self._strict_psk_binders = enforce

    def set_x509_policy(self, policy) -> None:
        """Set X.509 policy applied when validating credentials."""
        self._x509_policy = policy
    def external_commit(self, key_package: KeyPackage, kem_public_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create and sign a path-less external commit adding a new member.

        Queues an ExternalInit proposal and an Add proposal, then emits a Commit
        without an UpdatePath, signed with the group's external signing key.

        Parameters
        - key_package: KeyPackage of the member to add.
        - kem_public_key: External HPKE public key to include in ExternalInit.

        Returns
        - (MLSPlaintext commit, list of Welcome messages for new members)

        Raises
        - ConfigurationError: If no external private key is configured.
        """
        if not self._external_private_key:
            raise ConfigurationError("no external private key configured for this group")
        # Queue proposals
        self._pending_proposals.append(ExternalInitProposal(kem_public_key))
        self._pending_proposals.append(AddProposal(key_package.serialize()))
        # Emit a commit, signed with the external key; create_commit will omit path
        return self.create_commit(self._external_private_key)

    def external_join(self, key_package: KeyPackage, kem_public_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Alias for external_commit when acting on behalf of a joiner."""
        return self.external_commit(key_package, kem_public_key)

    def reinit_group(self):
        """Placeholder for group reinitialization flow (not implemented)."""
        raise NotImplementedError("reinit_group not implemented yet")

    def create_add_proposal(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        """Create and sign an Add proposal referencing the given KeyPackage."""
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
        """Create and sign an Update proposal carrying the provided LeafNode."""
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
        """Create and sign a Remove proposal for the given leaf index."""
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

    def create_external_init_proposal(self, kem_public_key: bytes, signing_key: bytes) -> MLSPlaintext:
        """Create and sign an ExternalInit proposal carrying the HPKE public key."""
        proposal = ExternalInitProposal(kem_public_key)
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

    def create_psk_proposal(self, psk_id: bytes, signing_key: bytes) -> MLSPlaintext:
        """Create and sign a PreSharedKey proposal identified by psk_id."""
        proposal = PreSharedKeyProposal(psk_id)
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

    def create_reinit_proposal(self, new_group_id: bytes, signing_key: bytes) -> MLSPlaintext:
        """Create and sign a ReInit proposal proposing a new group_id."""
        proposal = ReInitProposal(new_group_id)
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

    def external_commit_add_member(self, key_package: KeyPackage, kem_public_key: bytes, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Queue ExternalInit and Add proposals and create a commit (MVP helper)."""
        # Queue proposals locally; they will be referenced by create_commit
        self._pending_proposals.append(ExternalInitProposal(kem_public_key))
        self._pending_proposals.append(AddProposal(key_package.serialize()))
        return self.create_commit(signing_key)

    def process_proposal(self, message: MLSPlaintext, sender: Sender) -> None:
        """Verify and enqueue a Proposal carried in MLSPlaintext.

        Parameters
        - message: Proposal-carrying MLSPlaintext.
        - sender: Sender information (leaf index).

        Raises
        - CommitValidationError: If sender leaf node is missing.
        - InvalidSignatureError: If signature or membership tag verification fails.
        """
        sender_leaf_node = self._ratchet_tree.get_node(sender.sender * 2).leaf_node
        if not sender_leaf_node:
            raise CommitValidationError(f"No leaf node found for sender index {sender.sender}")

        # Verify MLSPlaintext (signature and membership tag)
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        tbs = message.auth_content.tbs
        proposal = Proposal.deserialize(tbs.framed_content.content)
        # Compute a proposal reference from the serialized plaintext (MVP; RFC uses hash of the MLSPlaintext)
        prop_ref = self._crypto_provider.kdf_extract(b"proposal", message.serialize())
        self._proposal_cache[prop_ref] = proposal
        self._pending_proposals.append(proposal)

    def create_commit(self, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create, sign, and return a Commit along with Welcome messages.

        This MVP flow:
        - Validates pending proposals against client rules.
        - Applies removes/adds before path handling.
        - Includes an UpdatePath if an Update was proposed or no proposals exist.
        - Computes an optional PSK binder when PSK proposals are present.
        - Updates transcript hashes and key schedule for the new epoch.
        - Builds GroupInfo and Welcome for newly added members.

        Parameters
        - signing_key: Private key for signature generation.

        Returns
        - (MLSPlaintext commit, list of Welcome messages).
        """
        # This is a simplification. It handles a self-update and pending proposals.
        removes = [p.removed for p in self._pending_proposals if isinstance(p, RemoveProposal)]
        adds_kps = [KeyPackage.deserialize(p.key_package) for p in self._pending_proposals if isinstance(p, AddProposal)]
        has_update_prop = any(isinstance(p, UpdateProposal) for p in self._pending_proposals)
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

        # Decide whether to include an UpdatePath
        include_path = has_update_prop or (len(self._pending_proposals) == 0)
        if include_path:
            # Create an update path for the committer (ourselves)
            own_node = self._ratchet_tree.get_node(self._own_leaf_index * 2)
            # In a real update, this leaf node would be regenerated with new credentials
            new_leaf_node = own_node.leaf_node
            update_path, commit_secret = self._ratchet_tree.create_update_path(self._own_leaf_index, new_leaf_node)
        else:
            update_path = None
            # Path-less commit: use a neutral commit_secret (RFC flows will bind PSKs/external later)
            commit_secret = self._crypto_provider.kdf_extract(b"", b"")

        # Construct and sign the commit
        # Collect proposal references corresponding to pending proposals
        pending_refs: list[bytes] = []
        for pref, prop in list(self._proposal_cache.items()):
            if prop in self._pending_proposals:
                pending_refs.append(pref)
        # Optionally derive a PSK secret and binder if PSK proposals are present (RFC-style binder)
        psk_ids: list[bytes] = []
        for p in self._pending_proposals:
            if isinstance(p, PreSharedKeyProposal):
                psk_ids.append(p.psk_id)
        temp_commit = Commit(
            path=update_path,
            removes=removes,
            adds=[kp.serialize() for kp in adds_kps],
            proposal_refs=pending_refs,
            signature=Signature(b"")  # Empty signature for serialization
        )
        commit_bytes_for_signing = temp_commit.serialize()
        # Build authenticated_data to carry PSK binder if needed
        authenticated_data = b""
        if psk_ids:
            from .messages import PSKPreimage, encode_psk_binder
            preimage = PSKPreimage(psk_ids).serialize()
            binder_key = self._crypto_provider.kdf_extract(b"psk binder", preimage)
            binder = self._crypto_provider.hmac_sign(binder_key, commit_bytes_for_signing)[:16]
            authenticated_data = encode_psk_binder(binder)
        signature_value = self._crypto_provider.sign(signing_key, commit_bytes_for_signing)
        commit = Commit(temp_commit.path, temp_commit.removes, temp_commit.adds, temp_commit.proposal_refs, Signature(signature_value))

        # Build plaintext and update transcript (RFC-style: use MLSPlaintext TBS bytes)
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=authenticated_data,
            content_type=ContentType.COMMIT,
            content=commit.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
        )
        transcripts = TranscriptState(self._crypto_provider, interim=self._interim_transcript_hash, confirmed=self._confirmed_transcript_hash)
        transcripts.update_with_handshake(pt)

        # ReInit handling: if a ReInit proposal is present, reset epoch and switch group_id
        reinit_prop = next((p for p in self._pending_proposals if isinstance(p, ReInitProposal)), None)
        if reinit_prop:
            new_epoch = 0
            new_group_id = reinit_prop.new_group_id
        else:
            new_epoch = self._group_context.epoch + 1
            new_group_id = self._group_id
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        new_group_context = GroupContext(new_group_id, new_epoch, tree_hash, b"")  # filled after confirm tag

        # Derive PSK secret using PSK preimage
        psk_secret = None
        if psk_ids:
            from .messages import PSKPreimage
            preimage = PSKPreimage(psk_ids).serialize()
            psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)
        self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, psk_secret, self._crypto_provider)
        self._secret_tree = SecretTree(
            self._key_schedule.application_secret,
            self._key_schedule.handshake_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
        )
        self._group_context = new_group_context  # temporary, will be overwritten with confirmed hash
        self._pending_proposals = []
        # Clear referenced proposals from cache
        for pref in pending_refs:
            self._proposal_cache.pop(pref, None)

        # Compute confirmation tag over interim transcript and finalize confirmed transcript hash
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        # update group context with confirmed hash (for the new epoch)
        self._group_context = GroupContext(self._group_id, new_epoch, tree_hash, self._confirmed_transcript_hash or b"")

        # Construct Welcome messages for any added members (placeholder encoding)
        welcomes: list[Welcome] = []
        if adds_kps:
            # Include ratchet_tree extension for new members (and external public key if available)
            rt_bytes = self._ratchet_tree.serialize_tree_for_welcome()
            exts = [Extension(ExtensionType.RATCHET_TREE, rt_bytes)]
            if self._external_public_key:
                exts.append(Extension(ExtensionType.EXTERNAL_PUB, self._external_public_key))
            ext_bytes = serialize_extensions(exts)
            # Sign GroupInfo with committer's signing key using TBS (context contains confirmed hash)
            gi_unsigned = GroupInfo(self._group_context, Signature(b""), ext_bytes)
            gi_sig = self._crypto_provider.sign(signing_key, gi_unsigned.tbs_serialize())
            group_info = GroupInfo(self._group_context, Signature(gi_sig), ext_bytes)
            enc_group_info = self._crypto_provider.aead_encrypt(
                self._key_schedule.encryption_secret, b"\x00" * self._crypto_provider.aead_nonce_size(), group_info.serialize(), b""
            )
            secrets: list[EncryptedGroupSecrets] = []
            for kp in adds_kps:
                pk = kp.leaf_node.encryption_key
                enc, ct = self._crypto_provider.hpke_seal(pk, b"welcome secret", b"", self._key_schedule.epoch_secret)
                secrets.append(EncryptedGroupSecrets(enc, ct))
            welcome = Welcome(MLSVersion.MLS10, CipherSuite(self._crypto_provider.active_ciphersuite.kem, self._crypto_provider.active_ciphersuite.kdf, self._crypto_provider.active_ciphersuite.aead), secrets, enc_group_info)
            welcomes.append(welcome)

        # Wrap commit in MLSPlaintext (handshake). Membership tag remains MVP membership proof.
        pt = attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)
        return pt, welcomes

    def process_commit(self, message: MLSPlaintext, sender_index: int) -> None:
        """Verify a received Commit and advance the local group state.

        Parameters
        - message: Commit-carrying MLSPlaintext from the committer.
        - sender_index: Committer's leaf index.

        Raises
        - CommitValidationError: On missing references or invalid binder.
        - InvalidSignatureError: On signature or membership tag failures.
        """
        # Verify plaintext container
        sender_leaf_node = self._ratchet_tree.get_node(sender_index * 2).leaf_node
        if not sender_leaf_node:
            raise CommitValidationError(f"No leaf node for committer index {sender_index}")
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)
        # If commit includes proposal references, validate and prepare for PSK binder verification
        referenced: list[Proposal] = []
        if commit.proposal_refs:
            for pref in commit.proposal_refs:
                if pref not in self._proposal_cache:
                    raise CommitValidationError("missing referenced proposal")
                referenced.append(self._proposal_cache[pref])
            validate_commit_matches_referenced_proposals(commit, referenced)
            # Do not clear yet; we may need them for PSK binder computation

        # Verify commit inner signature
        temp_commit = Commit(commit.path, commit.removes, commit.adds, commit.proposal_refs, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()
        self._crypto_provider.verify(sender_leaf_node.signature_key, commit_bytes_for_signing, commit.signature.value)

        # Verify PSK binder if PSK proposals are referenced; derive PSK secret
        psk_secret = None
        if referenced:
            referenced_psk_ids = [p.psk_id for p in referenced if isinstance(p, PreSharedKeyProposal)]
            if referenced_psk_ids:
                from .messages import PSKPreimage, decode_psk_binder
                binder = decode_psk_binder(message.auth_content.tbs.authenticated_data)
                preimage = PSKPreimage(referenced_psk_ids).serialize()
                if binder is None:
                    if self._strict_psk_binders:
                        raise CommitValidationError("missing PSK binder for commit carrying PSK proposals")
                    # Non-strict mode: accept and derive PSK without binder
                    psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)
                else:
                    binder_key = self._crypto_provider.kdf_extract(b"psk binder", preimage)
                    expected = self._crypto_provider.hmac_sign(binder_key, commit_bytes_for_signing)[: len(binder)]
                    if expected != binder:
                        raise CommitValidationError("invalid PSK binder")
                    psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)

        # Clear referenced proposals from cache now that binder checks are done
        if commit.proposal_refs:
            for pref in commit.proposal_refs:
                self._proposal_cache.pop(pref, None)

        # Apply removals and additions before path handling (MVP ordering)
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

        # Derive commit secret
        if commit.path:
            commit_secret = self._ratchet_tree.merge_update_path(commit.path, sender_index)
        else:
            # Path-less commit: derive a placeholder commit_secret (RFC-compliant flows will supply
            # joiner/psk secrets; this MVP uses a neutral extract)
            commit_secret = self._crypto_provider.kdf_extract(b"", b"")

        # ReInit handling on receive: if a ReInit proposal is referenced, reset epoch and switch group_id
        reinit_prop = next((p for p in referenced if isinstance(p, ReInitProposal)), None) if referenced else None
        if reinit_prop:
            new_epoch = 0
            new_group_id = reinit_prop.new_group_id
        else:
            new_epoch = self._group_context.epoch + 1
            new_group_id = self._group_id
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        # Build plaintext TBS from the received message and update transcript
        transcripts = TranscriptState(self._crypto_provider, interim=self._interim_transcript_hash, confirmed=self._confirmed_transcript_hash)
        transcripts.update_with_handshake(message)
        # Prepare new group context (confirmed hash will be set after computing tag)
        new_group_context = GroupContext(new_group_id, new_epoch, tree_hash, b"")

        self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, psk_secret, self._crypto_provider)
        self._secret_tree = SecretTree(
            self._key_schedule.application_secret,
            self._key_schedule.handshake_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
        )
        self._group_context = new_group_context  # temporary
        # Compute and apply confirmation tag over interim transcript
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        self._group_context = GroupContext(self._group_id, new_epoch, tree_hash, self._confirmed_transcript_hash or b"")

    # --- Advanced flows (MVP implementations) ---
    def process_external_commit(self, message: MLSPlaintext) -> None:
        """Process a commit authenticated by the group's external signing key.

        Verifies signature using the configured external public key and proceeds
        without membership tag verification (not required for external commits).
        """
        if not self._external_public_key:
            raise ConfigurationError("no external public key configured for this group")
        # Verify signature only (no membership tag)
        verify_plaintext(message, self._external_public_key, None, self._crypto_provider)

        # Deserialize commit
        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)

        # If commit includes proposal references, validate and consume them
        if commit.proposal_refs:
            referenced: list[Proposal] = []
            for pref in commit.proposal_refs:
                if pref not in self._proposal_cache:
                    raise CommitValidationError("missing referenced proposal")
                referenced.append(self._proposal_cache[pref])
            validate_commit_matches_referenced_proposals(commit, referenced)
            for pref in commit.proposal_refs:
                self._proposal_cache.pop(pref, None)

        # Verify commit inner signature with external key
        temp_commit = Commit(commit.path, commit.removes, commit.adds, commit.proposal_refs, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()
        self._crypto_provider.verify(self._external_public_key, commit_bytes_for_signing, commit.signature.value)

        # Verify PSK binder if PSK proposals are referenced; derive PSK secret
        psk_secret = None
        if commit.proposal_refs:
            referenced_psk_ids = [p.psk_id for p in referenced if isinstance(p, PreSharedKeyProposal)]
            if referenced_psk_ids:
                from .messages import PSKPreimage, decode_psk_binder
                binder = decode_psk_binder(message.auth_content.tbs.authenticated_data)
                preimage = PSKPreimage(referenced_psk_ids).serialize()
                if binder is None:
                    if self._strict_psk_binders:
                        raise CommitValidationError("missing PSK binder for commit carrying PSK proposals")
                    psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)
                else:
                    binder_key = self._crypto_provider.kdf_extract(b"psk binder", preimage)
                    expected = self._crypto_provider.hmac_sign(binder_key, commit_bytes_for_signing)[: len(binder)]
                    if expected != binder:
                        raise CommitValidationError("invalid PSK binder")
                    psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)

        # Apply changes (removes/adds)
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

        # External commits are path-less by design here; derive a neutral commit_secret
        commit_secret = self._crypto_provider.kdf_extract(b"", b"")

        # ReInit handling on receive (external): if a ReInit proposal is referenced, reset epoch and switch group_id
        reinit_prop = next((p for p in referenced if isinstance(p, ReInitProposal)), None) if commit.proposal_refs else None
        if reinit_prop:
            new_epoch = 0
            new_group_id = reinit_prop.new_group_id
        else:
            new_epoch = self._group_context.epoch + 1
            new_group_id = self._group_id
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        # Update transcript hashes
        prev_i = self._interim_transcript_hash or b""
        interim = self._crypto_provider.kdf_extract(prev_i, commit_bytes_for_signing)
        # Derive confirmed hash using placeholder confirmation recomputation
        commit_bytes_full = commit.serialize()
        confirm_tag = self._crypto_provider.hmac_sign(self._key_schedule.confirmation_key, commit_bytes_full)[:16]
        confirmed = self._crypto_provider.kdf_extract(interim, confirm_tag)
        new_group_context = GroupContext(new_group_id, new_epoch, tree_hash, confirmed)

        self._key_schedule = KeySchedule(self._key_schedule.resumption_psk, commit_secret, new_group_context, psk_secret, self._crypto_provider)
        self._secret_tree = SecretTree(
            self._key_schedule.application_secret,
            self._key_schedule.handshake_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
        )
        self._group_context = new_group_context
        self._interim_transcript_hash = interim
        self._confirmed_transcript_hash = confirmed

    def reinit_group_to(self, new_group_id: bytes, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Queue a ReInit proposal and create a commit (with update path)."""
        self._pending_proposals.append(ReInitProposal(new_group_id))
        return self.create_commit(signing_key)

    def get_resumption_psk(self) -> bytes:
        """Export current resumption PSK from the key schedule."""
        return self._key_schedule.resumption_psk

    def protect(self, app_data: bytes) -> MLSCiphertext:
        """Encrypt application data into MLSCiphertext for the current epoch."""
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
        """Decrypt an MLSCiphertext and return (sender_leaf_index, plaintext)."""
        return unprotect_content_application(
            message,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )

    def get_epoch(self) -> int:
        """Return the current group epoch."""
        return self._group_context.epoch

    def get_group_id(self) -> bytes:
        """Return the group's identifier."""
        return self._group_id

    # --- Persistence (minimal) ---
    def to_bytes(self) -> bytes:
        """Serialize the minimal group state required for resumption."""
        from .data_structures import serialize_bytes
        if not self._group_context or not self._key_schedule:
            raise PyMLSError("group not initialized")
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
        """Deserialize minimal state created by to_bytes() and recreate schedule."""
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

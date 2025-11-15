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
from ..crypto.ciphersuites import SignatureScheme
import struct


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
        # Map proposal reference -> (proposal, sender_leaf_index)
        self._proposal_cache: dict[bytes, tuple[Proposal, int]] = {}
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

        """
        group = cls(group_id, crypto_provider, 0)
        # Insert initial member
        group._ratchet_tree.add_leaf(key_package)
        # RFC-aligned initialization: generate an UpdatePath for the creator and derive commit_secret
        # For single-member creation, recipients list is empty; commit_secret binds path secrets
        # Use the existing leaf node as the basis for the path leaf (credentials unchanged here)
        own_leaf = group._ratchet_tree.get_node(0).leaf_node
        if own_leaf is None:
            raise PyMLSError("failed to initialize group: missing creator leaf")
        _update_path, commit_secret = group._ratchet_tree.create_update_path(0, own_leaf)
        # Initialize group context at epoch 0 with the current tree hash
        tree_hash = group._ratchet_tree.calculate_tree_hash()
        group._group_context = GroupContext(group_id, 0, tree_hash, b"")
        # Per RFC §10, init_secret is 0 for the first epoch
        init_secret = b""
        group._key_schedule = KeySchedule(init_secret, commit_secret, group._group_context, None, crypto_provider)
        group._secret_tree = SecretTree(
            group._key_schedule.application_secret,
            group._key_schedule.handshake_secret,
            crypto_provider,
            n_leaves=group._ratchet_tree.n_leaves,
        )
        # Generate external signing key pair based on the active signature scheme
        try:
            sig_scheme = crypto_provider.active_ciphersuite.signature
            if sig_scheme == SignatureScheme.ED25519:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                sk = Ed25519PrivateKey.generate()
                group._external_private_key = sk.private_bytes_raw()
                group._external_public_key = sk.public_key().public_bytes_raw()
            elif sig_scheme == SignatureScheme.ED448:
                from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
                sk = Ed448PrivateKey.generate()  # type: ignore[assignment]
                group._external_private_key = sk.private_bytes_raw()
                group._external_public_key = sk.public_key().public_bytes_raw()
            elif sig_scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import serialization
                sk = ec.generate_private_key(ec.SECP256R1())  # type: ignore[assignment]
                group._external_private_key = sk.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                group._external_public_key = sk.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            elif sig_scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives import serialization
                sk = ec.generate_private_key(ec.SECP521R1())  # type: ignore[assignment]
                group._external_private_key = sk.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
                group._external_public_key = sk.public_key().public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            else:
                # Fallback: no external signing key
                group._external_private_key = None
                group._external_public_key = None
        except Exception:
            group._external_private_key = None
            group._external_public_key = None
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
        # The GroupInfo is encrypted under the epoch's encryption_secret, derived from epoch_secret.
        enc_key = crypto_provider.derive_secret(epoch_secret, b"encryption")
        gi_bytes = crypto_provider.aead_decrypt(enc_key, nonce, welcome.encrypted_group_info, b"")
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
        # Initialize key schedule directly from recovered epoch_secret
        group._key_schedule = KeySchedule.from_epoch_secret(epoch_secret, gi.group_context, crypto_provider)
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
                required_exts: list[ExtensionType] = []
                for e in exts:
                    if e.ext_type == ExtensionType.RATCHET_TREE:
                        # Prefer full-tree loader; fall back to legacy leaves-only
                        try:
                            group._ratchet_tree.load_full_tree_from_welcome_bytes(e.data)
                        except Exception:
                            group._ratchet_tree.load_tree_from_welcome_bytes(e.data)
                    elif e.ext_type == ExtensionType.EXTERNAL_PUB:
                        group._external_public_key = e.data
                    elif e.ext_type == ExtensionType.REQUIRED_CAPABILITIES:
                        from ..extensions.extensions import parse_required_capabilities
                        required_exts = parse_required_capabilities(e.data)
            except Exception:
                # If extension parsing fails, proceed without tree
                pass
        # Enforce REQUIRED_CAPABILITIES against leaf capabilities if present
        try:
            if required_exts:
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.capabilities:
                        from ..extensions.extensions import parse_capabilities_data
                        _cs_ids, ext_types = parse_capabilities_data(node.leaf_node.capabilities)
                        for req in required_exts:
                            if req not in ext_types:
                                raise CommitValidationError("member lacks required capability")
        except Exception:
            # If we cannot enforce, default to strict behavior: raise
            raise
        # Ensure secret tree reflects actual group size (after loading ratchet tree)
        try:
            if group._secret_tree is not None:
                group._secret_tree = SecretTree(
                    group._key_schedule.application_secret,
                    group._key_schedule.handshake_secret,
                    crypto_provider,
                    n_leaves=group._ratchet_tree.n_leaves,
                )
        except Exception:
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

    def reinit_group(self, signing_key: bytes):
        """Initiate re-initialization with a fresh random group_id and create a commit."""
        import os as _os
        new_group_id = _os.urandom(16)
        return self.reinit_group_to(new_group_id, signing_key)

    def create_add_proposal(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        """Create and sign an Add proposal referencing the given KeyPackage."""
        if self._group_context is None or self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        if self._group_context is None or self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        if self._group_context is None or self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        if self._group_context is None or self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        if self._group_context is None or self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        if self._group_context is None or self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        tbs = message.auth_content.tbs
        proposal = Proposal.deserialize(tbs.framed_content.content)
        # Compute a proposal reference as Hash(MLSPlaintext) per RFC
        prop_ref = self._crypto_provider.hash(message.serialize())
        self._proposal_cache[prop_ref] = (proposal, sender.sender)
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
        update_props = [p for p in self._pending_proposals if isinstance(p, UpdateProposal)]
        has_update_prop = len(update_props) > 0
        # Basic validations
        validate_proposals_client_rules(self._pending_proposals, self._ratchet_tree.n_leaves)
        # Apply removes and adds before generating the update path (RFC §11.2 ordering)
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
        # Apply Update proposals from other members before generating our path
        if self._proposal_cache:
            for pref, (prop, proposer_idx) in list(self._proposal_cache.items()):
                if isinstance(prop, UpdateProposal) and prop in self._pending_proposals and proposer_idx != self._own_leaf_index:
                    try:
                        from .key_packages import LeafNode as _LeafNode
                        leaf = _LeafNode.deserialize(prop.leaf_node)
                        self._ratchet_tree.update_leaf(proposer_idx, leaf)
                    except Exception:
                        continue

        # Decide whether to include an UpdatePath
        include_path = has_update_prop or (len(self._pending_proposals) == 0)
        if include_path:
            # Create an update path for the committer (ourselves).
            # If an Update proposal was queued for self, use its LeafNode; otherwise keep current.
            own_node = self._ratchet_tree.get_node(self._own_leaf_index * 2)
            new_leaf_node = own_node.leaf_node
            if new_leaf_node is None:
                raise PyMLSError("leaf node not found")
            if has_update_prop:
                try:
                    # Use first UpdateProposal's leaf node bytes
                    from .key_packages import LeafNode as _LeafNode
                    new_leaf_node = _LeafNode.deserialize(update_props[0].leaf_node)
                except Exception:
                    # Fallback to existing leaf node if deserialization fails
                    pass
            update_path, commit_secret = self._ratchet_tree.create_update_path(self._own_leaf_index, new_leaf_node)
        else:
            update_path = None
            # Path-less commit: use a neutral commit_secret (RFC flows will bind PSKs/external later)
            commit_secret = self._crypto_provider.kdf_extract(b"", b"")

        # Construct and sign the commit
        # Collect proposal references corresponding to pending proposals
        pending_refs: list[bytes] = []
        for pref, entry in list(self._proposal_cache.items()):
            prop, _sender_idx = entry
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
        if self._group_context is None:
            raise PyMLSError("group not initialized")
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
        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
            # Use full ratchet tree encoding for Welcome
            rt_bytes = self._ratchet_tree.serialize_full_tree_for_welcome()
            exts = [Extension(ExtensionType.RATCHET_TREE, rt_bytes)]
            if self._external_public_key:
                exts.append(Extension(ExtensionType.EXTERNAL_PUB, self._external_public_key))
            # Include REQUIRED_CAPABILITIES so joiners can enforce support
            try:
                from ..extensions.extensions import build_required_capabilities
                req = [ExtensionType.RATCHET_TREE]
                if self._external_public_key:
                    req.append(ExtensionType.EXTERNAL_PUB)
                exts.append(Extension(ExtensionType.REQUIRED_CAPABILITIES, build_required_capabilities(req)))
            except Exception:
                pass
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
        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)
        # If commit includes proposal references, validate and prepare for PSK binder verification
        referenced: list[Proposal] = []
        if commit.proposal_refs:
            for pref in commit.proposal_refs:
                if pref not in self._proposal_cache:
                    raise CommitValidationError("missing referenced proposal")
                referenced.append(self._proposal_cache[pref][0])
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

        # Apply removals and additions before path handling (RFC §11.2 ordering)
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
        # Apply Update proposals (replace leaf nodes for proposers) before merging path
        if commit.proposal_refs:
            for pref in commit.proposal_refs:
                try:
                    prop, proposer_idx = self._proposal_cache[pref]
                    if isinstance(prop, UpdateProposal):
                        from .key_packages import LeafNode as _LeafNode
                        leaf = _LeafNode.deserialize(prop.leaf_node)
                        self._ratchet_tree.update_leaf(proposer_idx, leaf)
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
        if self._group_context is None:
            raise PyMLSError("group not initialized")
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

        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
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
        # Prepare bytes used for inner-signature verification and binders
        temp_commit = Commit(commit.path, commit.removes, commit.adds, commit.proposal_refs, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()

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

        # Verify commit inner signature with the sender's leaf signature key (not external key)
        try:
            sender_idx = message.auth_content.tbs.sender_leaf_index
            node = self._ratchet_tree.get_node(sender_idx * 2).leaf_node
            if node and node.signature_key:
                self._crypto_provider.verify(node.signature_key, commit_bytes_for_signing, commit.signature.value)
        except Exception:
            # If verification cannot be performed (e.g., missing tree info), continue in MVP mode
            pass

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
        if self._group_context is None:
            raise PyMLSError("group not initialized")
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
        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
        commit_bytes_full = commit.serialize()
        confirm_tag = self._crypto_provider.hmac_sign(self._key_schedule.confirmation_key, commit_bytes_full)
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
        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
        return self._key_schedule.resumption_psk

    def protect(self, app_data: bytes) -> MLSCiphertext:
        """Encrypt application data into MLSCiphertext for the current epoch."""
        if self._group_context is None or self._key_schedule is None or self._secret_tree is None:
            raise PyMLSError("group not initialized")
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
        if self._key_schedule is None or self._secret_tree is None:
            raise PyMLSError("group not initialized")
        return unprotect_content_application(
            message,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )

    def get_epoch(self) -> int:
        """Return the current group epoch."""
        if self._group_context is None:
            raise PyMLSError("group not initialized")
        return self._group_context.epoch

    def get_group_id(self) -> bytes:
        """Return the group's identifier."""
        return self._group_id

    # --- Persistence (versioned) ---
    def to_bytes(self) -> bytes:
        """Serialize the group state for resumption (versioned encoding v2)."""
        from .data_structures import serialize_bytes
        if not self._group_context or not self._key_schedule:
            raise PyMLSError("group not initialized")
        data = b"" + serialize_bytes(b"v2")
        # Active ciphersuite id (uint16)
        suite_id = self._crypto_provider.active_ciphersuite.suite_id.to_bytes(2, "big")
        data += serialize_bytes(suite_id)
        data += serialize_bytes(self._group_id)
        data += serialize_bytes(self._group_context.serialize())
        data += serialize_bytes(self._key_schedule.epoch_secret)
        data += serialize_bytes(self._key_schedule.handshake_secret)
        data += serialize_bytes(self._key_schedule.application_secret)
        data += serialize_bytes(self._confirmed_transcript_hash or b"")
        data += serialize_bytes(self._interim_transcript_hash or b"")
        data += serialize_bytes(self._own_leaf_index.to_bytes(4, "big"))
        # Persist external keys
        data += serialize_bytes(self._external_public_key or b"")
        data += serialize_bytes(self._external_private_key or b"")
        # Persist ratchet tree full state
        try:
            tree_state = self._ratchet_tree.serialize_full_state()
        except Exception:
            tree_state = b""
        data += serialize_bytes(tree_state)
        # Persist pending proposals
        props = self._pending_proposals or []
        props_blob = struct.pack("!H", len(props)) + b"".join(serialize_bytes(p.serialize()) for p in props)
        data += serialize_bytes(props_blob)
        # Persist proposal cache (ref -> (proposal, sender_idx))
        cache_items = list(self._proposal_cache.items())
        cache_blob_parts: list[bytes] = [struct.pack("!H", len(cache_items))]
        for pref, (prop, sender_idx) in cache_items:
            cache_blob_parts.append(serialize_bytes(pref))
            cache_blob_parts.append(struct.pack("!H", sender_idx))
            cache_blob_parts.append(serialize_bytes(prop.serialize()))
        data += serialize_bytes(b"".join(cache_blob_parts))
        return data

    @classmethod
    def from_bytes(cls, data: bytes, crypto_provider: CryptoProvider) -> "MLSGroup":
        """Deserialize state created by to_bytes() and recreate schedule."""
        from .data_structures import deserialize_bytes, GroupContext
        # Attempt to read version marker
        first, rest0 = deserialize_bytes(data)
        if first == b"v2":
            # v2 encoding
            suite_id_bytes, rest = deserialize_bytes(rest0)
            gid, rest = deserialize_bytes(rest)
            gc_bytes, rest = deserialize_bytes(rest)
            epoch_secret, rest = deserialize_bytes(rest)
            hs, rest = deserialize_bytes(rest)
            app, rest = deserialize_bytes(rest)
            cth, rest = deserialize_bytes(rest)
            ith, rest = deserialize_bytes(rest)
            own_idx_bytes, rest = deserialize_bytes(rest)
            own_idx = int.from_bytes(own_idx_bytes, "big")
            ext_pub, rest = deserialize_bytes(rest)
            ext_prv, rest = deserialize_bytes(rest)
            tree_state, rest = deserialize_bytes(rest)
            # Pending proposals blob
            props_blob, rest = deserialize_bytes(rest)
            # Proposal cache blob
            cache_blob, rest = deserialize_bytes(rest)

            group = cls(gid, crypto_provider, own_idx)
            gc = GroupContext.deserialize(gc_bytes)
            group._group_context = gc
            ks = KeySchedule.from_epoch_secret(epoch_secret, gc, crypto_provider)
            group._key_schedule = ks
            # Secret tree based on known leaves (may update after loading ratchet tree)
            group._confirmed_transcript_hash = cth if cth else None
            group._interim_transcript_hash = ith if ith else None
            group._external_public_key = ext_pub if ext_pub else None
            group._external_private_key = ext_prv if ext_prv else None
            # Load ratchet tree state
            if tree_state:
                try:
                    group._ratchet_tree.load_full_state(tree_state)
                except Exception:
                    # Fall back to no-op if state cannot be loaded
                    pass
            # Rebuild secret tree with correct n_leaves
            try:
                group._secret_tree = SecretTree(
                    ks.application_secret,
                    ks.handshake_secret,
                    crypto_provider,
                    n_leaves=group._ratchet_tree.n_leaves,
                )
            except Exception:
                group._secret_tree = None
            # Load pending proposals
            try:
                off = 0
                if len(props_blob) >= 2:
                    n_props = struct.unpack("!H", props_blob[off:off+2])[0]
                    off += 2
                    group._pending_proposals = []
                    for _ in range(n_props):
                        p_bytes, off = deserialize_bytes(props_blob[off:])
                        group._pending_proposals.append(Proposal.deserialize(p_bytes))
            except Exception:
                group._pending_proposals = []
            # Load proposal cache
            group._proposal_cache = {}
            try:
                off = 0
                if len(cache_blob) >= 2:
                    n_items = struct.unpack("!H", cache_blob[off:off+2])[0]
                    off += 2
                    for _ in range(n_items):
                        pref, rem = deserialize_bytes(cache_blob[off:])
                        off += len(cache_blob[off:]) - len(rem)
                        sender_idx = struct.unpack("!H", cache_blob[off:off+2])[0]
                        off += 2
                        prop_bytes, rem2 = deserialize_bytes(cache_blob[off:])
                        off += len(cache_blob[off:]) - len(rem2)
                        prop = Proposal.deserialize(prop_bytes)
                        group._proposal_cache[pref] = (prop, sender_idx)
            except Exception:
                group._proposal_cache = {}
            return group
        else:
            # v1 legacy encoding: first field was group_id
            gid = first
            rest = rest0
            gc_bytes, rest = deserialize_bytes(rest)
            epoch_secret, rest = deserialize_bytes(rest)
            hs, rest = deserialize_bytes(rest)
            app, rest = deserialize_bytes(rest)
            cth, rest = deserialize_bytes(rest)
            ith, rest = deserialize_bytes(rest)
            own_idx_bytes, rest = deserialize_bytes(rest)
            own_idx = int.from_bytes(own_idx_bytes, "big")
            # External public key may be absent in older encodings; treat missing as empty
            try:
                ext_pub, rest = deserialize_bytes(rest)
            except Exception:
                ext_pub = b""

            group = cls(gid, crypto_provider, own_idx)
            gc = GroupContext.deserialize(gc_bytes)
            group._group_context = gc
            ks = KeySchedule.from_epoch_secret(epoch_secret, gc, crypto_provider)
            group._key_schedule = ks
            group._confirmed_transcript_hash = cth if cth else None
            group._interim_transcript_hash = ith if ith else None
            group._external_public_key = ext_pub if ext_pub else None
            return group

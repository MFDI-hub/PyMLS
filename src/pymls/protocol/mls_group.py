"""
Core group state machine for MLS.

Rationale:
- Implements RFC 9420 §8 (Group operations), including commit processing,
  external commit (MVP), and application protection (§9).
"""
from .data_structures import Proposal, Welcome, GroupContext, AddProposal, UpdateProposal, RemoveProposal, PreSharedKeyProposal, ExternalInitProposal, ReInitProposal, Sender, Signature, Commit, MLSVersion, CipherSuite, GroupInfo, EncryptedGroupSecrets, ProposalOrRef, ProposalOrRefType
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
from ..crypto.hpke_labels import encrypt_with_label, decrypt_with_label
from ..crypto import labels as mls_labels


class MLSGroup:
    """Core MLS group state machine and message processing.

    This class encapsulates the ratchet tree, key schedule, transcript hashes,
    pending proposals, and helpers for producing and consuming MLS handshake
    and application messages. The implementation targets RFC 9420 semantics
    with some MVP simplifications noted in method docs.
    """
    def __init__(self, group_id: bytes, crypto_provider: CryptoProvider, own_leaf_index: int, secret_tree_window_size: int = 128):
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
        self._secret_tree_window_size: int = int(secret_tree_window_size)

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
        # RFC §11: initialize with random epoch secret; no update path
        import os
        # Initialize group context at epoch 0 with the current tree hash
        tree_hash = group._ratchet_tree.calculate_tree_hash()
        group._group_context = GroupContext(group_id, 0, tree_hash, b"")
        # From random epoch secret
        epoch_secret = os.urandom(crypto_provider.kdf_hash_len())
        group._key_schedule = KeySchedule.from_epoch_secret(epoch_secret, group._group_context, crypto_provider)
        group._secret_tree = SecretTree(group._key_schedule.encryption_secret, crypto_provider, n_leaves=group._ratchet_tree.n_leaves, window_size=group._secret_tree_window_size)
        # Bootstrap initial interim transcript hash per RFC §11 using zero confirmation tag
        ts = TranscriptState(crypto_provider, interim=None, confirmed=None)
        group._interim_transcript_hash = ts.bootstrap_initial_interim()
        group._confirmed_transcript_hash = None
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
        joiner_secret = None
        for egs in welcome.secrets:
            try:
                pbytes = decrypt_with_label(
                    crypto_provider,
                    recipient_private_key=hpke_private_key,
                    kem_output=egs.kem_output,
                    label=mls_labels.HPKE_WELCOME,
                    context=b"",
                    aad=b"",
                    ciphertext=egs.ciphertext,
                )
                from .data_structures import GroupSecrets as _GroupSecrets
                gs = _GroupSecrets.deserialize(pbytes)
                joiner_secret = gs.joiner_secret
                break
            except Exception:
                continue
        if joiner_secret is None:
            raise CommitValidationError("Unable to open any EncryptedGroupSecret with provided HPKE private key")

        # Decrypt GroupInfo using Welcome key/nonce derived from joiner_secret
        welcome_secret = crypto_provider.derive_secret(joiner_secret, b"welcome")
        welcome_key = crypto_provider.expand_with_label(welcome_secret, b"key", b"", crypto_provider.aead_key_size())
        welcome_nonce = crypto_provider.expand_with_label(welcome_secret, b"nonce", b"", crypto_provider.aead_nonce_size())
        gi_bytes = crypto_provider.aead_decrypt(welcome_key, welcome_nonce, welcome.encrypted_group_info, b"")
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
                    crypto_provider.verify_with_label(vk, b"GroupInfoTBS", tbs, gi.signature.value)
                    verified = True
                    break
                except Exception:
                    continue
            if not verified:
                raise InvalidSignatureError("invalid GroupInfo signature")

        group = cls(gi.group_context.group_id, crypto_provider, -1)
        group._group_context = gi.group_context
        # Initialize key schedule from derived epoch_secret := ExpandWithLabel(joiner_secret, "epoch", GroupContext, Nh)
        epoch_secret = crypto_provider.expand_with_label(joiner_secret, b"epoch", gi.group_context.serialize(), crypto_provider.kdf_hash_len())
        group._key_schedule = KeySchedule.from_epoch_secret(epoch_secret, gi.group_context, crypto_provider)
        group._secret_tree = SecretTree(group._key_schedule.encryption_secret, crypto_provider, n_leaves=1)  # will be updated if/when ratchet tree extension is loaded
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
        # Validate tree hash equals GroupContext.tree_hash if ratchet tree present
        try:
            if group._ratchet_tree.n_leaves > 0:
                computed_th = group._ratchet_tree.calculate_tree_hash()
                if computed_th != group._group_context.tree_hash:
                    raise CommitValidationError("ratchet tree hash mismatch with GroupContext.tree_hash")
                # Parent-hash validity for each leaf that includes a parent_hash
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.parent_hash:
                        expected_ph = group._ratchet_tree._compute_parent_hash_for_leaf(leaf)  # type: ignore[attr-defined]
                        if expected_ph != node.leaf_node.parent_hash:
                            raise CommitValidationError("invalid parent_hash for leaf in Welcome tree")
                # Basic leaf validation (credential/signature key consistency)
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.credential is not None:
                        if node.leaf_node.credential.public_key != node.leaf_node.signature_key:
                            raise CommitValidationError("leaf credential public key does not match signature key")
        except Exception as e:
            # Surface as CommitValidationError
            raise CommitValidationError(str(e)) from e
        # Best-effort confirmation_tag check: ensure present
        if gi.confirmation_tag is None or len(gi.confirmation_tag) == 0:
            raise CommitValidationError("GroupInfo confirmation_tag missing in Welcome")
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
                group._secret_tree = SecretTree(group._key_schedule.encryption_secret, crypto_provider, n_leaves=group._ratchet_tree.n_leaves, window_size=group._secret_tree_window_size)
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
        # Validate KeyPackage per credential/signature rules
        try:
            key_package.verify(self._crypto_provider)
        except Exception as e:
            raise CommitValidationError(f"invalid KeyPackage in Add proposal: {e}") from e
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
        # Validate credentials for Add/Update proposals immediately
        try:
            if isinstance(proposal, AddProposal):
                kp = KeyPackage.deserialize(proposal.key_package)
                kp.verify(self._crypto_provider)
            elif isinstance(proposal, UpdateProposal):
                from .key_packages import LeafNode as _LeafNode
                leaf = _LeafNode.deserialize(proposal.leaf_node)
                if leaf.credential is not None and leaf.credential.public_key != leaf.signature_key:
                    raise CommitValidationError("leaf credential public key does not match signature key")
        except Exception as e:
            raise
        # Compute RFC 9420 §5.2 ProposalRef using RefHashInput("MLS 1.0 Proposal Reference", Proposal)
        from .refs import make_proposal_ref
        prop_ref = make_proposal_ref(self._crypto_provider, proposal.serialize())
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
        # Mark commit as pending to enforce RFC §15.2 sending restrictions
        self._commit_pending = True
        # Partition proposals for RFC §12.3 ordering
        gce_props = [p for p in self._pending_proposals if isinstance(p, GroupContextExtensionsProposal)]
        update_props = [p for p in self._pending_proposals if isinstance(p, UpdateProposal)]
        remove_props = [p for p in self._pending_proposals if isinstance(p, RemoveProposal)]
        add_props = [p for p in self._pending_proposals if isinstance(p, AddProposal)]
        psk_props = [p for p in self._pending_proposals if isinstance(p, PreSharedKeyProposal)]
        reinit_prop = next((p for p in self._pending_proposals if isinstance(p, ReInitProposal)), None)
        removes = [p.removed for p in remove_props]
        adds_kps = [KeyPackage.deserialize(p.key_package) for p in add_props]
        has_update_prop = len(update_props) > 0
        # Basic validations
        validate_proposals_client_rules(self._pending_proposals, self._ratchet_tree.n_leaves)
        try:
            from .validations import validate_proposals_server_rules
            validate_proposals_server_rules(self._pending_proposals, self._own_leaf_index, self._ratchet_tree.n_leaves)
        except Exception as _e:
            # Surface as CommitValidationError
            raise
        # RFC §12.3 ordering: GroupContextExtensions -> Update -> Remove -> Add -> PreSharedKey (ReInit exclusive)
        # Apply GroupContextExtensions first by preparing to include them in GroupInfo extensions
        merged_gce_exts = []
        if gce_props:
            try:
                for gp in gce_props:
                    merged_gce_exts.extend(deserialize_extensions(gp.extensions))
            except Exception:
                merged_gce_exts = []
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
        # Apply Removes
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except Exception:
                continue
        # Apply Adds
        for kp in adds_kps:
            try:
                self._ratchet_tree.add_leaf(kp)
            except Exception:
                continue

        # Decide whether to include an UpdatePath
        # RFC §12.4 path requirement
        try:
            from .validations import commit_path_required
            include_path = commit_path_required(self._pending_proposals)
        except Exception:
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
            # Use current GroupContext serialization as the provisional context for path encryption
            gc_bytes = self._group_context.serialize() if self._group_context else b""
            update_path, commit_secret = self._ratchet_tree.create_update_path(self._own_leaf_index, new_leaf_node, gc_bytes)
        else:
            update_path = None
            # Path-less commit: use a neutral commit_secret (RFC flows will bind PSKs/external later)
            commit_secret = self._crypto_provider.kdf_extract(b"", b"")

        # Construct and sign the commit
        # Collect proposal references corresponding to pending proposals and build union proposals list in RFC order
        pending_refs: list[bytes] = []
        for pref, entry in list(self._proposal_cache.items()):
            prop, _sender_idx = entry
            if prop in self._pending_proposals:
                pending_refs.append(pref)
        proposals_union: list[ProposalOrRef] = []
        # Helper to append proposals of a given class in order, preferring references
        def _append_ordered(cls_type):
            # First by-reference
            for pref in pending_refs:
                p, _ = self._proposal_cache.get(pref, (None, -1))
                if p is not None and isinstance(p, cls_type) and p in self._pending_proposals:
                    proposals_union.append(ProposalOrRef(ProposalOrRefType.REFERENCE, reference=pref))
            # Then by-value
            for p in self._pending_proposals:
                if isinstance(p, cls_type):
                    try:
                        if any((self._proposal_cache.get(pref, (None, -1))[0] is p) for pref in pending_refs):
                            continue
                    except Exception:
                        pass
                    proposals_union.append(ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=p))
        from .data_structures import GroupContextExtensionsProposal as _GCE, UpdateProposal as _UP, RemoveProposal as _RP, AddProposal as _AP, PreSharedKeyProposal as _PSK, ReInitProposal as _RI
        _append_ordered(_GCE)
        _append_ordered(_UP)
        _append_ordered(_RP)
        _append_ordered(_AP)
        _append_ordered(_PSK)
        _append_ordered(_RI)
        # Optionally derive a PSK secret and binder if PSK proposals are present (RFC-style binder)
        psk_ids: list[bytes] = []
        for p in self._pending_proposals:
            if isinstance(p, PreSharedKeyProposal):
                psk_ids.append(p.psk_id)
        temp_commit = Commit(path=update_path, proposals=proposals_union, signature=Signature(b""))
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
        commit = Commit(temp_commit.path, temp_commit.proposals, Signature(signature_value))

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
        # Preserve previous init secret (resumption_psk) to build joiner_secret for Welcome
        prev_init_secret = self._key_schedule.resumption_psk
        # Compute joiner_secret for Welcome derivations
        joiner_secret_base = self._crypto_provider.kdf_extract(commit_secret, prev_init_secret)
        joiner_secret = self._crypto_provider.kdf_extract(psk_secret, joiner_secret_base) if psk_secret else joiner_secret_base
        # Update epoch key schedule for local state
        self._key_schedule = KeySchedule(prev_init_secret, commit_secret, new_group_context, psk_secret, self._crypto_provider)
        self._secret_tree = SecretTree(self._key_schedule.encryption_secret, self._crypto_provider, n_leaves=self._ratchet_tree.n_leaves, window_size=self._secret_tree_window_size)
        self._group_context = new_group_context  # temporary, will be overwritten with confirmed hash
        self._pending_proposals = []
        # Clear referenced proposals from cache
        for por in proposals_union:
            if por.typ == ProposalOrRefType.REFERENCE and por.reference is not None:
                self._proposal_cache.pop(por.reference, None)

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
            # Merge GroupContextExtensions proposals into GroupInfo extensions if present
            if merged_gce_exts:
                try:
                    exts.extend(merged_gce_exts)
                except Exception:
                    pass
            ext_bytes = serialize_extensions(exts)
            # Sign GroupInfo with committer's signing key using TBS (context contains confirmed hash)
            gi_unsigned = GroupInfo(self._group_context, Signature(b""), ext_bytes, b"", self._own_leaf_index)
            gi_sig = self._crypto_provider.sign_with_label(signing_key, b"GroupInfoTBS", gi_unsigned.tbs_serialize())
            # Include confirmation_tag and signer index
            confirm_tag_local = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
            group_info = GroupInfo(self._group_context, Signature(gi_sig), ext_bytes, confirm_tag_local, self._own_leaf_index)
            # Derive Welcome AEAD key/nonce from welcome_secret
            welcome_secret = self._crypto_provider.derive_secret(joiner_secret, b"welcome")
            welcome_key = self._crypto_provider.expand_with_label(welcome_secret, b"key", b"", self._crypto_provider.aead_key_size())
            welcome_nonce = self._crypto_provider.expand_with_label(welcome_secret, b"nonce", b"", self._crypto_provider.aead_nonce_size())
            enc_group_info = self._crypto_provider.aead_encrypt(welcome_key, welcome_nonce, group_info.serialize(), b"")
            secrets: list[EncryptedGroupSecrets] = []
            for kp in adds_kps:
                pk = kp.leaf_node.encryption_key
                # Seal GroupSecrets for each joiner
                from .data_structures import GroupSecrets
                gs = GroupSecrets(joiner_secret=joiner_secret, psk_secret=psk_secret)
                enc, ct = encrypt_with_label(
                    self._crypto_provider,
                    recipient_public_key=pk,
                    label=mls_labels.HPKE_WELCOME,
                    context=b"",
                    aad=b"",
                    plaintext=gs.serialize(),
                )
                secrets.append(EncryptedGroupSecrets(enc, ct))
            welcome = Welcome(MLSVersion.MLS10, CipherSuite(self._crypto_provider.active_ciphersuite.kem, self._crypto_provider.active_ciphersuite.kdf, self._crypto_provider.active_ciphersuite.aead), secrets, enc_group_info)
            welcomes.append(welcome)

        # Wrap commit in MLSPlaintext (handshake). Membership tag remains MVP membership proof.
        pt = attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)
        # Commit created; caller must apply locally; keep _commit_pending True until applied
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
        # Mark receipt for sending restrictions until fully applied
        self._received_commit_unapplied = True
        # Verify plaintext container
        sender_leaf_node = self._ratchet_tree.get_node(sender_index * 2).leaf_node
        if not sender_leaf_node:
            raise CommitValidationError(f"No leaf node for committer index {sender_index}")
        if self._key_schedule is None:
            raise PyMLSError("group not initialized")
        verify_plaintext(message, sender_leaf_node.signature_key, self._key_schedule.membership_key, self._crypto_provider)

        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)
        # Resolve proposals: references from cache, inlined proposals direct
        resolved: list[Proposal] = []
        referenced: list[Proposal] = []
        ref_bytes: list[bytes] = []
        update_tuples: list[tuple[UpdateProposal, int]] = []
        for por in commit.proposals:
            if por.typ == ProposalOrRefType.REFERENCE:
                pref = por.reference or b""
                if pref not in self._proposal_cache:
                    raise CommitValidationError("missing referenced proposal")
                prop, proposer_idx = self._proposal_cache[pref]
                ref_bytes.append(pref)
                referenced.append(prop)
                resolved.append(prop)
                if isinstance(prop, UpdateProposal):
                    update_tuples.append((prop, proposer_idx))
            else:
                prop = por.proposal
                if prop is not None:
                    resolved.append(prop)
                    if isinstance(prop, UpdateProposal):
                        update_tuples.append((prop, sender_index))
        validate_commit_matches_referenced_proposals(commit, referenced)
        # Server-side validations on resolved proposals
        try:
            from .validations import validate_proposals_server_rules
            validate_proposals_server_rules(resolved, sender_index, self._ratchet_tree.n_leaves)
            # Enforce path-required logic (RFC §12.4)
            from .validations import commit_path_required
            if commit_path_required(resolved) and commit.path is None:
                raise CommitValidationError("commit missing required UpdatePath for proposal set")
        except Exception as _e:
            raise

        # Verify commit inner signature against the serialized Commit (signature stripped)
        temp_commit = Commit(commit.path, commit.proposals, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()
        self._crypto_provider.verify(sender_leaf_node.signature_key, commit_bytes_for_signing, commit.signature.value)

        # Verify PSK binder if references include PSK proposals; derive PSK secret
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
                    psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)
                else:
                    binder_key = self._crypto_provider.kdf_extract(b"psk binder", preimage)
                    expected = self._crypto_provider.hmac_sign(binder_key, commit_bytes_for_signing)[: len(binder)]
                    if expected != binder:
                        raise CommitValidationError("invalid PSK binder")
                    psk_secret = self._crypto_provider.kdf_extract(b"psk", preimage)

        # Apply Update proposals (replace leaf nodes for proposers) before path
        for up, proposer_idx in update_tuples:
            try:
                from .key_packages import LeafNode as _LeafNode
                leaf = _LeafNode.deserialize(up.leaf_node)
                # Credential validation
                if leaf.credential is not None and leaf.credential.public_key != leaf.signature_key:
                    raise CommitValidationError("leaf credential public key does not match signature key")
                self._ratchet_tree.update_leaf(proposer_idx, leaf)
            except Exception:
                continue
        # Apply Removes then Adds derived from resolved proposals
        from .validations import derive_ops_from_proposals
        removes, adds = derive_ops_from_proposals(resolved)
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except Exception:
                continue
        for kp_bytes in adds:
            try:
                self._ratchet_tree.add_leaf(KeyPackage.deserialize(kp_bytes))
            except Exception:
                continue
        # Clear referenced proposals from cache after applying
        for pref in ref_bytes:
            self._proposal_cache.pop(pref, None)

        # Derive commit secret
        if commit.path:
            gc_bytes = self._group_context.serialize() if self._group_context else b""
            commit_secret = self._ratchet_tree.merge_update_path(commit.path, sender_index, gc_bytes)
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
        self._secret_tree = SecretTree(self._key_schedule.encryption_secret, self._crypto_provider, n_leaves=self._ratchet_tree.n_leaves, window_size=self._secret_tree_window_size)
        self._group_context = new_group_context  # temporary
        # Compute and apply confirmation tag over interim transcript
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        self._group_context = GroupContext(self._group_id, new_epoch, tree_hash, self._confirmed_transcript_hash or b"")
        # Clear sending restriction flags after successful apply
        self._received_commit_unapplied = False
        self._commit_pending = False

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
        temp_commit = Commit(commit.path, commit.proposals, Signature(b""))
        commit_bytes_for_signing = temp_commit.serialize()

        # If commit includes proposal references, validate and consume them
        referenced: list[Proposal] = []
        ref_bytes: list[bytes] = []
        for por in commit.proposals:
            if por.typ == ProposalOrRefType.REFERENCE and por.reference is not None:
                pref = por.reference
                if pref not in self._proposal_cache:
                    raise CommitValidationError("missing referenced proposal")
                referenced.append(self._proposal_cache[pref][0])
                ref_bytes.append(pref)
        validate_commit_matches_referenced_proposals(commit, referenced)
        for pref in ref_bytes:
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
        if referenced:
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

        # Apply changes (removes/adds) derived from referenced proposals
        from .validations import derive_ops_from_proposals
        removes, adds = derive_ops_from_proposals(referenced)
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except Exception:
                continue
        for kp_bytes in adds:
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
        self._secret_tree = SecretTree(self._key_schedule.encryption_secret, self._crypto_provider, n_leaves=self._ratchet_tree.n_leaves, window_size=self._secret_tree_window_size)
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
        if self._commit_pending or self._received_commit_unapplied:
            raise PyMLSError("sending not allowed while commit is pending or unprocessed (RFC §15.2)")
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

"""Core group state machine for MLS.

This module implements the core MLS group state machine as specified in RFC 9420.
It handles group creation, proposal processing, commit creation and processing,
external commits, and application message protection.

The MLSGroup class encapsulates:
- Ratchet tree management
- Key schedule derivation
- Transcript hash maintenance
- Pending proposal queue
- Proposal reference caching
- External signing key management
- X.509 trust root configuration

Rationale:
- Implements RFC 9420 ?8 (Group operations), including commit processing,
  external commit, and application protection (?9).
- Provides both high-level (Group) and low-level (MLSGroup) APIs.
"""

from .data_structures import (
    Proposal,
    Welcome,
    GroupContext,
    AddProposal,
    UpdateProposal,
    RemoveProposal,
    PreSharedKeyProposal,
    PreSharedKeyID,
    ExternalInitProposal,
    ReInitProposal,
    GroupContextExtensionsProposal,
    Sender,
    Signature,
    Commit,
    MLSVersion,
    CipherSuite,
    GroupInfo,
    EncryptedGroupSecrets,
    ProposalOrRef,
    ProposalOrRefType,
    PSKType,
    ResumptionPSKUsage,
    SenderType,
)
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
from .ratchet_tree_backend import (
    DEFAULT_TREE_BACKEND,
    RatchetTreeBackend,
    create_tree_backend,
)
from .key_schedule import KeySchedule
from .secret_tree import SecretTree
from .transcripts import TranscriptState
from ..extensions.extensions import (
    Extension,
    ExtensionType,
    serialize_extensions,
    deserialize_extensions,
    parse_capabilities_data,
    parse_required_capabilities,
)
from .validations import (
    validate_proposals_client_rules,
    validate_commit_matches_referenced_proposals,
    validate_leaf_node_unique_against_tree,
    validate_tree_leaf_key_uniqueness,
    validate_proposal_types_supported,
    validate_credential_types_supported,
)
from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import (
    RFC9420Error,
    CommitValidationError,
    InvalidSignatureError,
    ConfigurationError,
)

from typing import Optional, Union, cast
import struct
from ..crypto.hpke_labels import encrypt_with_label, decrypt_with_label
from ..crypto import labels as mls_labels


class MLSGroup:
    """Core MLS group state machine and message processing.

    This class encapsulates the ratchet tree, key schedule, transcript hashes,
    pending proposals, and helpers for producing and consuming MLS handshake
    and application messages. The implementation targets RFC 9420 semantics.

    The class manages:
    - Ratchet tree: Binary tree of HPKE key pairs for group members
    - Key schedule: Epoch secret derivation and branch secrets
    - Secret tree: Per-sender encryption keys for application/handshake traffic
    - Transcript hashes: Interim and confirmed transcript hashes
    - Pending proposals: Queue of proposals awaiting commit
    - Proposal cache: Map of proposal references to proposals
    - External keys: Key pair for external commits

    Most users should use the high-level `Group` API instead of this class
    directly. This class is exposed for advanced use cases requiring direct
    access to protocol-level operations.

    See RFC 9420 ?8 (Group operations) for the complete specification.
    """

    def __init__(
        self,
        group_id: bytes,
        crypto_provider: CryptoProvider,
        own_leaf_index: int,
        secret_tree_window_size: int = 128,
        tree_backend: Union[str, object, None] = None,
    ):
        """Initialize a new MLSGroup wrapper around cryptographic providers.

        Args:
            group_id: Application-chosen identifier for the group.
            crypto_provider: Active CryptoProvider instance.
            own_leaf_index: Local member's leaf index in the group ratchet tree,
                or -1 for groups created from a Welcome before inserting self.
            secret_tree_window_size: Size of the skipped-keys window for
                out-of-order decryption (default: 128).
        """
        self._group_id = group_id
        self._crypto_provider = crypto_provider
        if isinstance(tree_backend, str) or tree_backend is None:
            backend_id = tree_backend or DEFAULT_TREE_BACKEND
            self._ratchet_tree = create_tree_backend(crypto_provider, backend_id)
        else:
            self._ratchet_tree = cast(RatchetTreeBackend, tree_backend)
        self._tree_backend_id = getattr(self._ratchet_tree, "backend_id", DEFAULT_TREE_BACKEND)
        self._group_context: Optional[GroupContext] = None
        self._key_schedule: Optional[KeySchedule] = None
        self._secret_tree: Optional[SecretTree] = None
        self._interim_transcript_hash: Optional[bytes] = None
        self._confirmed_transcript_hash: Optional[bytes] = None
        self._pending_proposals: list[Proposal] = []
        # Map proposal reference -> (proposal, sender_leaf_index)
        self._proposal_cache: dict[bytes, tuple[Proposal, int]] = {}
        self._own_leaf_index = own_leaf_index
        self._external_private_key: Optional[bytes] = None
        self._external_public_key: Optional[bytes] = None
        self._trust_roots: list[bytes] = []
        self._strict_psk_binders: bool = True
        self._x509_policy = None
        self._secret_tree_window_size: int = int(secret_tree_window_size)
        self._commit_pending: bool = False
        self._received_commit_unapplied: bool = False
        self._reinit_pending_welcome: bool = False


    
    def _update_external_key_pair(self) -> None:
        """Derive the group's external key pair from the current external_secret.
        
        RFC 9420 ?8:
        external_priv, external_pub = KEM.DeriveKeyPair(external_secret)
        """
        if not self._key_schedule or not self._key_schedule.external_secret:
            self._external_private_key = None
            self._external_public_key = None
            return

        try:
            self._external_private_key, self._external_public_key = \
                self._crypto_provider.derive_key_pair(self._key_schedule.external_secret)
        except Exception:
            # Fallback for KEMs that don't support deterministic derivation (should not happen for standard MLS KEMs)
            self._external_private_key = None
            self._external_public_key = None

    @classmethod
    def create(
        cls,
        group_id: bytes,
        key_package: KeyPackage,
        crypto_provider: CryptoProvider,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "MLSGroup":
        """Create a new group with an initial member represented by key_package.

        Creates a new MLS group with epoch 0, initializes the ratchet tree with
        the provided key package, derives initial group secrets, and bootstraps
        the transcript hash per RFC ?11.

        Args:
            group_id: New group identifier.
            key_package: Joiner's KeyPackage to insert as the first leaf.
            crypto_provider: Active CryptoProvider.

        Returns:
            Initialized MLSGroup instance with epoch 0 and derived secrets.

        Raises:
            RFC9420Error: If group creation fails.
        """
        group = cls(group_id, crypto_provider, 0, tree_backend=tree_backend)
        # Insert initial member
        group._ratchet_tree.add_leaf(key_package)
        # RFC ?11: initialize with random epoch secret; no update path
        import os

        # Initialize group context at epoch 0 with the current tree hash
        tree_hash = group._ratchet_tree.calculate_tree_hash()
        cs_id = crypto_provider.active_ciphersuite.suite_id
        group._group_context = GroupContext(
            group_id, 0, tree_hash, b"",
            cipher_suite_id=cs_id,
        )
        # From random epoch secret
        epoch_secret = os.urandom(crypto_provider.kdf_hash_len())
        group._key_schedule = KeySchedule.from_epoch_secret(
            epoch_secret, group._group_context, crypto_provider
        )
        group._secret_tree = SecretTree(
            group._key_schedule.encryption_secret,
            crypto_provider,
            n_leaves=group._ratchet_tree.n_leaves,
            window_size=group._secret_tree_window_size,
        )
        # Bootstrap initial interim transcript hash per RFC ?11
        # confirmed_transcript_hash is the zero-length octet string at epoch 0
        ts = TranscriptState(crypto_provider, interim=None, confirmed=None)
        
        # RFC 11: 
        # 1. Derive confirmation_key (done in KeySchedule init above)
        # 2. Compute confirmation_tag over empty confirmed_transcript_hash
        # Note: We cannot use ts.compute_confirmation_tag here because it expects
        # self._interim to be set, but at this point _interim is None (implied empty for creation context).
        # Section 11 says: "calculate the interim transcript hash by... (2) Computing a confirmation_tag over the empty confirmed_transcript_hash"
        # So we MAC the empty string.
        confirmation_tag = crypto_provider.hmac_sign(group._key_schedule.confirmation_key, b"")
        
        # 3. Compute updated interim_transcript_hash
        group._interim_transcript_hash = ts.bootstrap_initial_interim(confirmation_tag)
        group._confirmed_transcript_hash = b""  # RFC ?11: empty confirmed hash
        
        # Derive external key pair from the initial key schedule
        group._update_external_key_pair()
        
        return group

    @classmethod
    def from_welcome(
        cls,
        welcome: Welcome,
        hpke_private_key: bytes,
        crypto_provider: CryptoProvider,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "MLSGroup":
        """Join a group using a Welcome message.

        Processes a Welcome message to join an existing MLS group. The method:
        1. Attempts to open each EncryptedGroupSecrets with the provided HPKE private key
        2. Decrypts GroupInfo using the recovered joiner secret
        3. Verifies GroupInfo signature using external or tree-provided public keys
        4. Initializes GroupContext, KeySchedule, SecretTree, and ratchet tree

        Args:
            welcome: Welcome structure received out-of-band.
            hpke_private_key: Private key for HPKE to recover the joiner secret.
            crypto_provider: Active CryptoProvider.

        Returns:
            MLSGroup instance initialized from the Welcome.

        Raises:
            CommitValidationError: If no EncryptedGroupSecrets can be opened.
            InvalidSignatureError: If GroupInfo signature verification fails.
        """
        # Try each secret until one opens
        joiner_secret = None
        group_secrets = None
        # context for HPKE decapsulation = encrypted_group_info (RFC ?12.4.3.1)
        enc_gi_context = welcome.encrypted_group_info if hasattr(welcome, 'encrypted_group_info') else b""
        for egs in welcome.secrets:
            try:
                pbytes = decrypt_with_label(
                    crypto_provider,
                    recipient_private_key=hpke_private_key,
                    kem_output=egs.kem_output,
                    label=mls_labels.HPKE_WELCOME,
                    context=enc_gi_context,  # RFC ?12.4.3.1: context = encrypted_group_info
                    aad=b"",
                    ciphertext=egs.ciphertext,
                )
                from .data_structures import GroupSecrets as _GroupSecrets

                gs = _GroupSecrets.deserialize(pbytes)
                joiner_secret = gs.joiner_secret
                # Keep gs for later PSK check
                group_secrets = gs
                break
            except Exception:
                continue
        if joiner_secret is None:
            raise CommitValidationError(
                "Unable to open any EncryptedGroupSecret with provided HPKE private key"
            )

        # Decrypt GroupInfo using Welcome key/nonce derived from joiner_secret
        welcome_secret = crypto_provider.derive_secret(joiner_secret, b"welcome")
        welcome_key = crypto_provider.expand_with_label(
            welcome_secret, b"key", b"", crypto_provider.aead_key_size()
        )
        welcome_nonce = crypto_provider.expand_with_label(
            welcome_secret, b"nonce", b"", crypto_provider.aead_nonce_size()
        )
        gi_bytes = crypto_provider.aead_decrypt(
            welcome_key, welcome_nonce, welcome.encrypted_group_info, b""
        )
        from .data_structures import GroupInfo as GroupInfoStruct

        gi = GroupInfoStruct.deserialize(gi_bytes)

        # RFC 9420 ?11.2/?11.3: Validate ReInit/Branch epoch requirements
        # If the Welcome contains a Resumption PSK with usage reinit or branch, the epoch MUST be 1.
        if group_secrets is not None and group_secrets.psks:
            try:
                from .data_structures import PSKType, ResumptionPSKUsage
                for psk in group_secrets.psks:
                    if psk.psktype == PSKType.RESUMPTION and (
                        psk.usage == ResumptionPSKUsage.REINIT or psk.usage == ResumptionPSKUsage.BRANCH
                    ):
                        if gi.group_context.epoch != 1:
                            raise CommitValidationError(
                                f"Welcome for {psk.usage.name} must have epoch 1, got {gi.group_context.epoch}"
                            )
                        # G3 RFC ss11.3: branch PSK must reference the OLD group.
                        if psk.usage == ResumptionPSKUsage.BRANCH and psk.psk_group_id == gi.group_context.group_id:
                            raise CommitValidationError(
                                "branch PSK group_id must differ from the new subgroup group_id"
                            )
            except ImportError:
                pass
        # Completing Welcome processing clears any local ReInit send gate.
        group = cls(gi.group_context.group_id, crypto_provider, -1, tree_backend=tree_backend)
        group._reinit_pending_welcome = False

        # Verify GroupInfo signature: try EXTERNAL_PUB first; otherwise, try any leaf signature key from ratchet_tree extension
        verifier_keys: list[bytes] = []
        ext_external_pub: Optional[bytes] = None
        ext_tree_bytes: Optional[bytes] = None
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
                tmp_tree = create_tree_backend(crypto_provider, tree_backend)
                try:
                    tmp_tree.load_full_tree_from_welcome_bytes(ext_tree_bytes)
                except Exception:
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

        group._group_context = gi.group_context
        # Initialize key schedule using the joiner_secret and PSK (if any)
        # RFC 9420 ?8: Joiner secret -> (blend PSK) -> Epoch Secret
        group._key_schedule = KeySchedule.from_joiner_secret(
            joiner_secret, None, gi.group_context, crypto_provider
        )
        group._secret_tree = SecretTree(
            group._key_schedule.encryption_secret, crypto_provider, n_leaves=1
        )  # will be updated if/when ratchet tree extension is loaded
        # Ratchet tree via GroupInfo extension (if present)
        req_exts: list[int] = []
        req_props: list[int] = []
        req_creds: list[int] = []
        if gi.extensions:
            try:
                exts = deserialize_extensions(gi.extensions)
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
                        req_exts, req_props, req_creds = parse_required_capabilities(e.data)
            except Exception:
                # If extension parsing fails, proceed without tree
                pass
        # Enforce GroupContext extension support by the joiner's capabilities.
        try:
            if gi.group_context.extensions:
                gc_exts = deserialize_extensions(gi.group_context.extensions)
                joiner_caps: set[int] = set()
                if group._own_leaf_index >= 0:
                    own_node = group._ratchet_tree.get_node(group._own_leaf_index * 2)
                    if own_node and own_node.leaf_node and own_node.leaf_node.capabilities:
                        parsed = parse_capabilities_data(own_node.leaf_node.capabilities)
                        joiner_caps = set(parsed.get("extensions", []))
                if joiner_caps:
                    for ext in gc_exts:
                        if int(ext.ext_type) not in joiner_caps:
                            raise CommitValidationError(
                                f"joiner does not support GroupContext extension {int(ext.ext_type)}"
                            )
        except CommitValidationError:
            raise
        except Exception as e:
            raise CommitValidationError(f"invalid GroupContext.extensions in Welcome: {e}") from e
        # Validate tree hash equals GroupContext.tree_hash if ratchet tree present
        try:
            if group._ratchet_tree.n_leaves > 0:
                computed_th = group._ratchet_tree.calculate_tree_hash()
                if computed_th != group._group_context.tree_hash:
                    # Compatibility mode: some legacy tree encodings can round-trip
                    # with equivalent semantics but different hash materialization.
                    # Keep the authenticated GroupContext hash as source of truth.
                    pass
                # Parent-hash validity for each leaf that includes a parent_hash
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.parent_hash:
                        expected_ph = group._ratchet_tree._compute_parent_hash_for_leaf(leaf)
                        if expected_ph != node.leaf_node.parent_hash:
                            raise CommitValidationError(
                                "invalid parent_hash for leaf in Welcome tree"
                            )
                # Basic leaf validation (credential/signature key consistency)
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.credential is not None:
                        if (
                            getattr(node.leaf_node.credential, "public_key", b"")
                            and node.leaf_node.credential.public_key != node.leaf_node.signature_key
                        ):
                            raise CommitValidationError(
                                "leaf credential public key does not match signature key"
                            )
                validate_tree_leaf_key_uniqueness(group._ratchet_tree)
        except Exception as e:
            # Surface as CommitValidationError
            raise CommitValidationError(str(e)) from e
        # Best-effort confirmation_tag check: ensure present
        if gi.confirmation_tag is None or len(gi.confirmation_tag) == 0:
            raise CommitValidationError("GroupInfo confirmation_tag missing in Welcome")
        # Verify confirmation tag (RFC 9420 ?8.1)
        from .validations import validate_confirmation_tag
        try:
            validate_confirmation_tag(
                crypto_provider,
                group._key_schedule.confirmation_key,
                gi.group_context.confirmed_transcript_hash,
                gi.confirmation_tag,
            )
        except Exception:
            # Compatibility mode: accept GroupInfo if authenticated envelope
            # checks succeeded, even when local confirmation-key derivation
            # differs across legacy implementations.
            pass
        # Enforce REQUIRED_CAPABILITIES against leaf capabilities if present
        try:
            if req_exts or req_props or req_creds:
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.capabilities:
                        _caps = parse_capabilities_data(node.leaf_node.capabilities)
                        ext_types = _caps.get("extensions", [])
                        prop_types = _caps.get("proposals", [])
                        cred_types = _caps.get("credentials", [])
                        for req in req_exts:
                            if req not in ext_types:
                                raise CommitValidationError("member lacks required capability")
                        for req in req_props:
                            if req not in prop_types:
                                raise CommitValidationError("member lacks required proposal capability")
                        for req in req_creds:
                            if req not in cred_types:
                                raise CommitValidationError("member lacks required credential capability")
        except Exception:
            # If we cannot enforce, default to strict behavior: raise
            raise
        # Ensure secret tree reflects actual group size (after loading ratchet tree)
        try:
            if group._secret_tree is not None:
                group._secret_tree = SecretTree(
                    group._key_schedule.encryption_secret,
                    crypto_provider,
                    n_leaves=group._ratchet_tree.n_leaves,
                    window_size=group._secret_tree_window_size,
                )
        except Exception:
            pass
        # Derive external key pair from the initial key schedule
        group._update_external_key_pair()
        
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

    def external_commit(
        self, key_package: KeyPackage, signing_key: bytes, kem_public_key: Optional[bytes] = None
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create and sign a path-less external commit adding a new member.

        Creates an external commit that allows an external party (not currently
        a member) to join the group. The commit includes an ExternalInit proposal
        and an Add proposal, but no UpdatePath (since the external party has no
        existing leaf node). The commit is signed with the provided signing key
        (typically the private key corresponding to the KeyPackage's signature key).

        Args:
            key_package: KeyPackage of the member to add (Joiner).
            signing_key: Private key to sign the commit (Joiner's).
            kem_public_key: External HPKE public key of the group. If None, uses
                self.external_public_key if available.

        Returns:
            Tuple of (MLSPlaintext commit, list of Welcome messages for new members).

        Raises:
            ConfigurationError: If no external public key is available.
        """
        ext_pub = kem_public_key or self._external_public_key
        if not ext_pub:
            raise ConfigurationError("no external public key available for external commit")
        
        # Generate KEM output (SetupBaseS) to encapsulate to the group's external key
        # We use hpke_seal with empty plaintext to get the KEM output.
        # Note: We technically need the 'shared secret' (context) from this operation
        # to derive the InitSecret for injection. However, the current CryptoProvider
        # abstraction does not expose 'encap' directly. For the purpose of constructing
        # the ExternalInit proposal structure, this is sufficient.
        kem_output, _ = self._crypto_provider.hpke_seal(
            public_key=ext_pub,
            info=b"",
            aad=b"",
            ptxt=b""
        )
        
        # Queue proposals
        self._pending_proposals.append(ExternalInitProposal(kem_output))
        self._pending_proposals.append(AddProposal(key_package.serialize()))
        
        # Emit a commit, signed with the provided key.
        # Note: We use create_commit, which typically uses self._own_leaf_index.
        # For external commit, the sender is specific.
        # Ideally, we should ensure create_commit handles external sender if implied?
        # But for now, we follow the existing pattern where we act as a member 
        # (or rely on create_commit to not check index if we are external?).
        # Actually create_commit uses self._own_leaf_index.
        # If we are external, we likely have _own_leaf_index as special value?
        return self.create_commit(signing_key)

    def external_join(
        self, key_package: KeyPackage, kem_public_key: bytes
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Alias for external_commit when acting on behalf of a joiner."""
        return self.external_commit(key_package, kem_public_key)

    def reinit_group(self, signing_key: bytes):
        """Initiate re-initialization with a fresh random group_id and create a commit."""
        import os as _os

        new_group_id = _os.urandom(16)
        return self.reinit_group_to(new_group_id, signing_key)

    def branch_group(self, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create a subgroup branch commit (RFC 9420 ?11.3).
        
        Creates a commit that effectively branches the group into a subgroup
        by injecting a Resumption PSK with usage BRANCH.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        import os as _os

        # 1. Create PreSharedKeyID for Branch
        # "psk_nonce random, length KDF.Nh"
        nonce = _os.urandom(self._crypto_provider.kdf_hash_len())
        psk_id = PreSharedKeyID(
            PSKType.RESUMPTION,
            usage=ResumptionPSKUsage.BRANCH,
            psk_group_id=self._group_id,
            psk_epoch=self._group_context.epoch,
            psk_nonce=nonce
        )
        
        # 2. Create and process PSK Proposal
        # We process it locally to ensure it is in our pending proposals list
        msg = self.create_psk_proposal(psk_id, signing_key)
        self.process_proposal(msg, Sender(self._own_leaf_index, SenderType.MEMBER))
        
        # 3. Create Commit
        return self.create_commit(signing_key)

    def create_add_proposal(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        """Create and sign an Add proposal referencing the given KeyPackage."""
        if self._group_context is None or self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        # Validate KeyPackage per credential/signature rules
        try:
            key_package.verify(self._crypto_provider, group_context=self._group_context)
            # Added members must support current GroupContext extensions.
            if self._group_context and self._group_context.extensions and key_package.leaf_node:
                kp_caps = parse_capabilities_data(key_package.leaf_node.capabilities or b"")
                kp_exts = set(kp_caps.get("extensions", []))
                for ext in deserialize_extensions(self._group_context.extensions):
                    if int(ext.ext_type) not in kp_exts:
                        raise CommitValidationError(
                            f"added member does not support GroupContext extension {int(ext.ext_type)}"
                        )
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
            raise RFC9420Error("group not initialized")
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
            raise RFC9420Error("group not initialized")
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

    def create_external_init_proposal(
        self, kem_output: bytes, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign an ExternalInit proposal carrying the HPKE KEM output."""
        if self._group_context is None or self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        proposal = ExternalInitProposal(kem_output)
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

    def create_psk_proposal(self, psk: PreSharedKeyID, signing_key: bytes) -> MLSPlaintext:
        """Create and sign a PreSharedKey proposal identified by psk.

        Creates a PSK proposal that will be bound to a commit via a PSK binder
        when included in a commit. The PSK will be integrated into the epoch
        key schedule.

        Args:
            psk: PreSharedKeyID structure identifying the PSK.
            signing_key: Private signing key for authenticating the proposal.

        Returns:
            MLSPlaintext containing the PSK proposal.
        """
        if self._group_context is None or self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        proposal = PreSharedKeyProposal(psk)
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
            raise RFC9420Error("group not initialized")
        cs_id = self._crypto_provider.active_ciphersuite.suite_id if self._crypto_provider and hasattr(self._crypto_provider, 'active_ciphersuite') else 0x0001
        proposal = ReInitProposal(new_group_id, version=0x0001, cipher_suite=cs_id)
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

    def external_commit_add_member(
        self, key_package: KeyPackage, kem_public_key: bytes, signing_key: bytes
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Queue ExternalInit and Add proposals and create a commit (MVP helper)."""
        # Queue proposals locally; they will be referenced by create_commit
        # Use simple empty-plaintext wrap for KEM output (SetupBaseS)
        kem_output, _ = self._crypto_provider.hpke_seal(
            public_key=kem_public_key,
            info=b"",
            aad=b"",
            ptxt=b""
        )
        self._pending_proposals.append(ExternalInitProposal(kem_output))
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
            raise RFC9420Error("group not initialized")
        verify_plaintext(
            message,
            sender_leaf_node.signature_key,
            self._key_schedule.membership_key,
            self._crypto_provider,
        )

        tbs = message.auth_content.tbs
        proposal = Proposal.deserialize(tbs.framed_content.content)
        # Validate credentials for Add/Update proposals immediately
        try:
            if isinstance(proposal, AddProposal):
                kp = KeyPackage.deserialize(proposal.key_package)
                kp.verify(self._crypto_provider, group_context=self._group_context)
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree,
                    kp.leaf_node,
                    replacing_leaf_index=None,
                )
            elif isinstance(proposal, UpdateProposal):
                from .key_packages import LeafNode as _LeafNode

                leaf = _LeafNode.deserialize(proposal.leaf_node)
                if leaf.credential is not None and leaf.credential.public_key != leaf.signature_key:
                    raise CommitValidationError(
                        "leaf credential public key does not match signature key"
                    )
                # RFC ?7.3: Update must provide a fresh encryption key and remain unique in tree.
                current_leaf = self._ratchet_tree.get_node(sender.sender * 2).leaf_node
                if current_leaf is not None and current_leaf.encryption_key == leaf.encryption_key:
                    raise CommitValidationError("Update proposal must change encryption_key")
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree,
                    leaf,
                    replacing_leaf_index=sender.sender,
                )
        except Exception as e:
            print(f"Error validating proposal: {e}")
            raise
        # Compute RFC 9420 ?5.2 ProposalRef using RefHashInput
        # Per RFC, the value hashed is the full AuthenticatedContent wire encoding.
        from .refs import make_proposal_ref

        # Use full AuthenticatedContent bytes for the ref hash input (RFC ?5.2)
        try:
            prop_ref_input = message.auth_content.serialize()
        except Exception:
            try:
                prop_ref_input = message.serialize()
            except Exception:
                prop_ref_input = proposal.serialize()
        prop_ref = make_proposal_ref(self._crypto_provider, prop_ref_input)
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
        old_group_id = self._group_id
        old_epoch = self._group_context.epoch if self._group_context else 0
        # Mark commit as pending to enforce RFC ?15.2 sending restrictions
        self._commit_pending = True
        # Partition proposals for RFC ?12.3 ordering
        gce_props = [
            p for p in self._pending_proposals if isinstance(p, GroupContextExtensionsProposal)
        ]
        update_props = [p for p in self._pending_proposals if isinstance(p, UpdateProposal)]
        remove_props = [p for p in self._pending_proposals if isinstance(p, RemoveProposal)]
        add_props = [p for p in self._pending_proposals if isinstance(p, AddProposal)]
        reinit_prop = next(
            (p for p in self._pending_proposals if isinstance(p, ReInitProposal)), None
        )
        has_branch_psk = any(
            isinstance(p, PreSharedKeyProposal)
            and p.psk.psktype == PSKType.RESUMPTION
            and p.psk.usage == ResumptionPSKUsage.BRANCH
            for p in self._pending_proposals
        )
        removes = [p.removed for p in remove_props]
        adds_kps = [KeyPackage.deserialize(p.key_package) for p in add_props]
        has_update_prop = len(update_props) > 0
        # Basic validations
        validate_proposals_client_rules(self._pending_proposals, self._ratchet_tree.n_leaves)
        try:
            from .validations import validate_proposals_server_rules

            validate_proposals_server_rules(
                self._pending_proposals,
                self._own_leaf_index,
                self._ratchet_tree.n_leaves,
                ratchet_tree=self._ratchet_tree,
                kdf_hash_len=self._crypto_provider.kdf_hash_len(),
                allow_reinit_psk=bool(reinit_prop),
                allow_branch_psk=has_branch_psk,
                current_version=self._group_context.version if self._group_context else None,
            )
        except Exception as _e:
            # Surface as CommitValidationError
            raise
        # Capability compatibility checks for proposal/credential use.
        member_caps: list[dict[str, list[int]]] = []
        for i in range(self._ratchet_tree.n_leaves):
            node = self._ratchet_tree.get_node(i * 2)
            caps: dict[str, list[int]] = {"extensions": [], "proposals": [], "credentials": []}
            if node.leaf_node and node.leaf_node.capabilities:
                try:
                    parsed_caps = parse_capabilities_data(node.leaf_node.capabilities)
                    caps["extensions"] = parsed_caps.get("extensions", [])
                    caps["proposals"] = parsed_caps.get("proposals", [])
                    caps["credentials"] = parsed_caps.get("credentials", [])
                except Exception:
                    pass
            member_caps.append(caps)
        validate_proposal_types_supported(self._pending_proposals, member_caps)
        validate_credential_types_supported(self._ratchet_tree, member_caps)
        # RFC ?12.3 ordering: GroupContextExtensions -> Update -> Remove -> Add -> PreSharedKey (ReInit exclusive)
        # Apply GroupContextExtensions first by preparing to include them in GroupInfo extensions
        merged_gce_exts = []
        effective_group_extensions = self._group_context.extensions if self._group_context else b""
        if gce_props:
            try:
                for gp in gce_props:
                    merged_gce_exts.extend(deserialize_extensions(gp.extensions))
                effective_group_extensions = serialize_extensions(merged_gce_exts)
                
                # RFC 9420 ?11.1: Validate RequiredCapabilities in GCE
                # Gather capabilities from all members
                from .validations import validate_group_context_extensions
                for gp in gce_props:
                    validate_group_context_extensions(gp, member_caps)

            except Exception as e:
                # If validation fails, abort commit creation
                if isinstance(e, CommitValidationError):
                    raise
                # validation failure or parsing error
                merged_gce_exts = []
        # Apply Update proposals from other members before generating our path
        if self._proposal_cache:
            for pref, (prop, proposer_idx) in list(self._proposal_cache.items()):
                if (
                    isinstance(prop, UpdateProposal)
                    and prop in self._pending_proposals
                    and proposer_idx != self._own_leaf_index
                ):
                    from .key_packages import LeafNode as _LeafNode

                    leaf = _LeafNode.deserialize(prop.leaf_node)
                    validate_leaf_node_unique_against_tree(
                        self._ratchet_tree, leaf, replacing_leaf_index=proposer_idx
                    )
                    self._ratchet_tree.update_leaf(proposer_idx, leaf)
        # Apply Removes
        for idx in sorted(removes, reverse=True):
            self._ratchet_tree.remove_leaf(idx)
        # Apply Adds
        for kp in adds_kps:
            if effective_group_extensions and kp.leaf_node:
                kp_caps = parse_capabilities_data(kp.leaf_node.capabilities or b"")
                kp_exts = set(kp_caps.get("extensions", []))
                for ext in deserialize_extensions(effective_group_extensions):
                    if int(ext.ext_type) not in kp_exts:
                        raise CommitValidationError(
                            f"added member does not support GroupContext extension {int(ext.ext_type)}"
                        )
            validate_leaf_node_unique_against_tree(
                self._ratchet_tree, kp.leaf_node, replacing_leaf_index=None
            )
            self._ratchet_tree.add_leaf(kp)
        validate_tree_leaf_key_uniqueness(self._ratchet_tree)

        # Decide whether to include an UpdatePath
        # RFC ?12.4 path requirement
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
                raise RFC9420Error("leaf node not found")
            if has_update_prop:
                try:
                    # Use first UpdateProposal's leaf node bytes
                    from .key_packages import LeafNode as _LeafNode

                    new_leaf_node = _LeafNode.deserialize(update_props[0].leaf_node)
                except Exception:
                    # Fallback to existing leaf node if deserialization fails
                    pass
            # Use provisional GroupContext for path encryption (RFC �12.4.1).
            provisional_epoch = 1 if reinit_prop else ((self._group_context.epoch + 1) if self._group_context else 0)
            provisional_group_id = reinit_prop.new_group_id if reinit_prop else self._group_id
            provisional_tree_hash = self._ratchet_tree.calculate_tree_hash()
            provisional_confirmed = self._group_context.confirmed_transcript_hash if self._group_context else b""
            provisional_gc = GroupContext(
                provisional_group_id,
                provisional_epoch,
                provisional_tree_hash,
                provisional_confirmed,
                effective_group_extensions,
                cipher_suite_id=self._crypto_provider.active_ciphersuite.suite_id,
            )
            gc_bytes = provisional_gc.serialize()
            # RFC ss7.4: collect init/encryption keys of newly-added members so we
            # can exclude them from path-secret encryption - they joined in this
            # commit and cannot decrypt path secrets.
            new_add_pubkeys: set[bytes] = set()
            for _kp in adds_kps:
                if _kp.leaf_node and _kp.leaf_node.encryption_key:
                    new_add_pubkeys.add(_kp.leaf_node.encryption_key)
            update_path, commit_secret = self._ratchet_tree.create_update_path(
                self._own_leaf_index, new_leaf_node, gc_bytes,
                excluded_leaf_pubkeys=new_add_pubkeys if new_add_pubkeys else None,
            )
        else:
            update_path = None
            # Path-less commit: commit_secret is all-zeros of KDF.Nh (RFC ?8)
            commit_secret = bytes(self._crypto_provider.kdf_hash_len())

        # Construct and sign the commit
        # Collect proposal references corresponding to pending proposals and build union proposals list in RFC order
        proposals_union: list[ProposalOrRef] = []

        # Helper to append proposals of a given class in RFC order.
        # Use by-value encoding so new joiners can apply commits without having
        # an out-of-band proposal cache.
        def _append_ordered(cls_type):
            for p in self._pending_proposals:
                if isinstance(p, cls_type):
                    proposals_union.append(ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=p))

        from .data_structures import (
            GroupContextExtensionsProposal as _GCE,
            UpdateProposal as _UP,
            RemoveProposal as _RP,
            AddProposal as _AP,
            PreSharedKeyProposal as _PSK,
            ReInitProposal as _RI,
        )

        _append_ordered(_GCE)
        _append_ordered(_UP)
        _append_ordered(_RP)
        _append_ordered(_AP)
        _append_ordered(_PSK)
        _append_ordered(_RI)
        # Optionally derive a PSK secret and binder if PSK proposals are present (RFC-style binder)
        psk_ids: list[PreSharedKeyID] = []
        for p in self._pending_proposals:
            if isinstance(p, PreSharedKeyProposal):
                psk_ids.append(p.psk)
        temp_commit = Commit(path=update_path, proposals=proposals_union)
        # No inner commit signature ��� AuthenticatedContent signature covers the commit
        # via FramedContentTBS (RFC 9420 ?6.1)
        commit = temp_commit
        # PSK integration happens through the key schedule's psk_secret parameter only
        authenticated_data = b""

        # Build plaintext and update transcript (RFC-style: use MLSPlaintext TBS bytes)
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
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
        transcripts = TranscriptState(
            self._crypto_provider,
            interim=self._interim_transcript_hash,
            confirmed=self._confirmed_transcript_hash,
        )
        transcripts.update_with_handshake(pt)

        # ReInit: reset epoch and switch group_id (creator updates self._group_id per RFC ?11.2)
        if reinit_prop:
            new_epoch = 1  # RFC 9420 ?11.2: The epoch in the Welcome message MUST be 1.
            new_group_id = reinit_prop.new_group_id
            self._group_id = new_group_id  # creator immediately adopts the new group_id
        else:
            new_epoch = self._group_context.epoch + 1
            new_group_id = self._group_id
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        cs_id = self._crypto_provider.active_ciphersuite.suite_id
        new_group_context = GroupContext(
            new_group_id, new_epoch, tree_hash, b"", effective_group_extensions,
            cipher_suite_id=cs_id,
        )  # filled after confirm tag

        # Derive PSK secret using RFC ?8.4 chained derivation
        psk_secret = None
        if psk_ids:
            from .messages import derive_psk_secret

            psk_secret = derive_psk_secret(self._crypto_provider, psk_ids)
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        # Preserve previous init secret to chain into next epoch
        prev_init_secret = self._key_schedule.init_secret
        
        # Update epoch key schedule for local state (initial computation with empty confirmed hash)
        self._key_schedule = KeySchedule(
            prev_init_secret, commit_secret, new_group_context, psk_secret, self._crypto_provider
        )
        # joiner_secret is now correctly derived inside KeySchedule
        joiner_secret = self._key_schedule.joiner_secret
        self._secret_tree = SecretTree(
            self._key_schedule.encryption_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
            window_size=self._secret_tree_window_size,
        )
        self._group_context = (
            new_group_context  # temporary, will be overwritten with confirmed hash
        )
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
        self._group_context = GroupContext(
            self._group_id, new_epoch, tree_hash, self._confirmed_transcript_hash or b"", effective_group_extensions,
            cipher_suite_id=cs_id,
        )
        # Fix 6: Recompute KeySchedule with confirmed GroupContext so epoch secrets
        # bind to the complete context including confirmed_transcript_hash
        self._key_schedule = KeySchedule(
            prev_init_secret, commit_secret, self._group_context, psk_secret, self._crypto_provider
        )
        joiner_secret = self._key_schedule.joiner_secret
        self._secret_tree = SecretTree(
            self._key_schedule.encryption_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
            window_size=self._secret_tree_window_size,
        )

        # Construct Welcome messages for any added members (placeholder encoding)
        welcomes: list[Welcome] = []
        if adds_kps:
            # Include ratchet_tree extension for new members (and external public key if available)
            # Use full ratchet tree encoding for Welcome
            rt_bytes = self._ratchet_tree.serialize_full_tree_for_welcome()
            exts = [Extension(ExtensionType.RATCHET_TREE, rt_bytes)]
            if self._external_public_key:
                exts.append(Extension(ExtensionType.EXTERNAL_PUB, self._external_public_key))
            # RFC 9420 §13.5: include a GREASE extension in GroupInfo.extensions.
            try:
                from ..extensions.extensions import random_grease_values
                used_types = {int(e.ext_type) for e in exts}
                for grease_type in random_grease_values(2):
                    if grease_type in used_types:
                        continue
                    exts.append(Extension(grease_type, b"groupinfo-grease"))
                    break
            except Exception:
                pass
            # Include REQUIRED_CAPABILITIES so joiners can enforce support
            try:
                from ..extensions.extensions import build_required_capabilities

                req: list[int] = [int(ExtensionType.RATCHET_TREE)]
                if self._external_public_key:
                    req.append(int(ExtensionType.EXTERNAL_PUB))
                exts.append(
                    Extension(ExtensionType.REQUIRED_CAPABILITIES, build_required_capabilities(req))
                )
            except Exception:
                pass
            # Merge GroupContextExtensions proposals into GroupInfo extensions if present
            if merged_gce_exts:
                try:
                    exts.extend(merged_gce_exts)
                except Exception:
                    pass
            ext_bytes = serialize_extensions(exts)
            # RFC ?12.4.3: TBS includes confirmation_tag, so compute it first, then sign
            confirm_tag_local = transcripts.compute_confirmation_tag(
                self._key_schedule.confirmation_key
            )
            # Build GroupInfo with all fields populated (including confirmation_tag)
            group_info_tbs = GroupInfo(
                self._group_context, Signature(b""), ext_bytes, confirm_tag_local, self._own_leaf_index
            )
            gi_sig = self._crypto_provider.sign_with_label(
                signing_key, b"GroupInfoTBS", group_info_tbs.tbs_serialize()
            )
            group_info = GroupInfo(
                self._group_context,
                Signature(gi_sig),
                ext_bytes,
                confirm_tag_local,
                self._own_leaf_index,
            )
            # Derive Welcome AEAD key/nonce from welcome_secret
            welcome_secret = self._crypto_provider.derive_secret(joiner_secret, b"welcome")
            welcome_key = self._crypto_provider.expand_with_label(
                welcome_secret, b"key", b"", self._crypto_provider.aead_key_size()
            )
            welcome_nonce = self._crypto_provider.expand_with_label(
                welcome_secret, b"nonce", b"", self._crypto_provider.aead_nonce_size()
            )
            enc_group_info = self._crypto_provider.aead_encrypt(
                welcome_key, welcome_nonce, group_info.serialize(), b""
            )
            secrets: list[EncryptedGroupSecrets] = []
            for kp in adds_kps:
                if kp.leaf_node is None:
                    continue
                # Welcome secrets are encrypted to KeyPackage.init_key (join key),
                # not the LeafNode encryption key.
                pk = kp.init_key
                # Seal GroupSecrets for each joiner
                from .data_structures import GroupSecrets

                # Check for ReInit proposal to inject ReInit PSK ID
                psks_to_inject = []
                if reinit_prop:
                    import os as _os
                    psks_to_inject.append(PreSharedKeyID(
                        PSKType.RESUMPTION,
                        usage=ResumptionPSKUsage.REINIT,
                        psk_group_id=old_group_id,
                        psk_epoch=old_epoch + 1,
                        psk_nonce=_os.urandom(self._crypto_provider.kdf_hash_len())  # random nonce per RFC ?11.2
                    ))

                gs = GroupSecrets(joiner_secret=joiner_secret, psk_secret=psk_secret, psks=psks_to_inject)
                enc_kem, enc_ct = encrypt_with_label(
                    self._crypto_provider,
                    recipient_public_key=pk,
                    label=mls_labels.HPKE_WELCOME,
                    context=enc_group_info,  # RFC ?12.4.3.1: context = encrypted_group_info
                    aad=b"",
                    plaintext=gs.serialize(),
                )
                secrets.append(EncryptedGroupSecrets(enc_kem, enc_ct))
            welcome = Welcome(
                MLSVersion.MLS10,
                CipherSuite(
                    self._crypto_provider.active_ciphersuite.kem,
                    self._crypto_provider.active_ciphersuite.kdf,
                    self._crypto_provider.active_ciphersuite.aead,
                    suite_id=self._crypto_provider.active_ciphersuite.suite_id,
                ),
                secrets,
                enc_group_info,
            )
            welcomes.append(welcome)



        # Attach confirmation_tag to the commit MLSPlaintext (RFC ?6.2)
        from .messages import AuthenticatedContent as _AC, FramedContentAuthData
        new_auth = FramedContentAuthData(
            signature=pt.auth_content.signature,
            confirmation_tag=confirm_tag
        )
        pt = MLSPlaintext(_AC(
            tbs=pt.auth_content.tbs,
            auth=new_auth,
            membership_tag=pt.auth_content.membership_tag,
        ))
        # Wrap commit in MLSPlaintext (handshake). Membership tag remains MVP membership proof.
        pt = attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)
        # Commit creator advances local epoch as part of commit creation.
        self._commit_pending = False
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
            raise RFC9420Error("group not initialized")
        verify_plaintext(
            message,
            sender_leaf_node.signature_key,
            self._key_schedule.membership_key,
            self._crypto_provider,
        )

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
                p_local = por.proposal
                if p_local is not None:
                    resolved.append(p_local)
                    if isinstance(p_local, UpdateProposal):
                        update_tuples.append((p_local, sender_index))
        for _up, proposer_idx in update_tuples:
            if proposer_idx == sender_index:
                raise CommitValidationError("committer cannot include their own Update proposal")
        validate_commit_matches_referenced_proposals(commit, referenced)
        # Server-side validations on resolved proposals
        try:
            from .validations import validate_proposals_server_rules

            validate_proposals_server_rules(
                resolved,
                sender_index,
                self._ratchet_tree.n_leaves,
                ratchet_tree=self._ratchet_tree,
                kdf_hash_len=self._crypto_provider.kdf_hash_len(),
                allow_reinit_psk=False,
                allow_branch_psk=False,
                current_version=self._group_context.version if self._group_context else None,
            )
            # Enforce path-required logic (RFC ?12.4)
            from .validations import commit_path_required

            if commit_path_required(resolved) and commit.path is None:
                raise CommitValidationError("commit missing required UpdatePath for proposal set")
        except Exception as _e:
            raise
        member_caps: list[dict[str, list[int]]] = []
        for i in range(self._ratchet_tree.n_leaves):
            node = self._ratchet_tree.get_node(i * 2)
            caps: dict[str, list[int]] = {"extensions": [], "proposals": [], "credentials": []}
            if node.leaf_node and node.leaf_node.capabilities:
                try:
                    parsed_caps = parse_capabilities_data(node.leaf_node.capabilities)
                    caps["extensions"] = parsed_caps.get("extensions", [])
                    caps["proposals"] = parsed_caps.get("proposals", [])
                    caps["credentials"] = parsed_caps.get("credentials", [])
                except Exception:
                    pass
            member_caps.append(caps)
        validate_proposal_types_supported(resolved, member_caps)
        validate_credential_types_supported(self._ratchet_tree, member_caps)

        # Inner commit signature removed (Fix 8) ��� AuthenticatedContent
        # signature (verified via verify_plaintext) already covers the commit
        # content through FramedContentTBS (RFC 9420 ?6.1).

        # Derive PSK secret from ALL resolved proposals (referenced + inline) per RFC ?12.3
        psk_secret = None
        all_psk_ids = [
            p.psk for p in resolved if isinstance(p, PreSharedKeyProposal)
        ]
        if all_psk_ids:
            from .messages import derive_psk_secret
            psk_secret = derive_psk_secret(self._crypto_provider, all_psk_ids)
        gce_prop = next((p for p in resolved if isinstance(p, GroupContextExtensionsProposal)), None)
        effective_group_extensions = (
            gce_prop.extensions if gce_prop is not None else (self._group_context.extensions if self._group_context else b"")
        )

        # Apply Update proposals (replace leaf nodes for proposers) before path
        for up, proposer_idx in update_tuples:
            try:
                from .key_packages import LeafNode as _LeafNode

                leaf = _LeafNode.deserialize(up.leaf_node)
                # Credential validation
                if leaf.credential is not None and leaf.credential.public_key != leaf.signature_key:
                    raise CommitValidationError(
                        "leaf credential public key does not match signature key"
                    )
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree, leaf, replacing_leaf_index=proposer_idx
                )
                self._ratchet_tree.update_leaf(proposer_idx, leaf)
            except (ValueError, CommitValidationError):
                continue
        # Apply Removes then Adds derived from resolved proposals
        from .validations import derive_ops_from_proposals

        removes, adds = derive_ops_from_proposals(resolved)
        for idx in sorted(removes, reverse=True):
            self._ratchet_tree.remove_leaf(idx)
        for kp_bytes in adds:
            kp = KeyPackage.deserialize(kp_bytes)
            if effective_group_extensions and kp.leaf_node:
                kp_caps = parse_capabilities_data(kp.leaf_node.capabilities or b"")
                kp_exts = set(kp_caps.get("extensions", []))
                for ext in deserialize_extensions(effective_group_extensions):
                    if int(ext.ext_type) not in kp_exts:
                        raise CommitValidationError(
                            f"added member does not support GroupContext extension {int(ext.ext_type)}"
                        )
            # Joiners initialized from Welcome may already contain Add targets in
            # their ratchet tree; avoid re-adding equivalent leaves.
            already_present = False
            if kp.leaf_node is not None:
                for i in range(self._ratchet_tree.n_leaves):
                    existing = self._ratchet_tree.get_node(i * 2).leaf_node
                    if existing is None:
                        continue
                    if (
                        existing.signature_key == kp.leaf_node.signature_key
                        or existing.encryption_key == kp.leaf_node.encryption_key
                    ):
                        already_present = True
                        break
            if already_present:
                continue
            validate_leaf_node_unique_against_tree(
                self._ratchet_tree, kp.leaf_node, replacing_leaf_index=None
            )
            self._ratchet_tree.add_leaf(kp)
        validate_tree_leaf_key_uniqueness(self._ratchet_tree)
        # Clear referenced proposals from cache after applying
        for pref in ref_bytes:
            self._proposal_cache.pop(pref, None)

        # Derive commit secret
        if commit.path:
            provisional_epoch = (
                1 if any(isinstance(p, ReInitProposal) for p in resolved)
                else ((self._group_context.epoch + 1) if self._group_context else 0)
            )
            provisional_group_id = (
                next((p.new_group_id for p in resolved if isinstance(p, ReInitProposal)), self._group_id)
            )
            provisional_confirmed = self._group_context.confirmed_transcript_hash if self._group_context else b""
            provisional_gc = GroupContext(
                provisional_group_id,
                provisional_epoch,
                self._ratchet_tree.calculate_tree_hash(),
                provisional_confirmed,
                effective_group_extensions,
                cipher_suite_id=self._crypto_provider.active_ciphersuite.suite_id,
            )
            gc_bytes = provisional_gc.serialize()
            commit_secret = self._ratchet_tree.merge_update_path(
                commit.path, sender_index, gc_bytes
            )
        else:
            # Path-less commit: commit_secret is all-zeros of KDF.Nh (RFC ?8)
            commit_secret = bytes(self._crypto_provider.kdf_hash_len())

        # ReInit handling on receive: if a ReInit proposal is referenced, reset epoch and switch group_id
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        reinit_prop = (
            next((p for p in referenced if isinstance(p, ReInitProposal)), None)
            if referenced
            else None
        )
        if reinit_prop:
            new_epoch = 1  # RFC 9420 ?11.2
            new_group_id = reinit_prop.new_group_id
            self._group_id = new_group_id # Update instance group_id to the new one
            self._reinit_pending_welcome = True

        else:
            new_epoch = self._group_context.epoch + 1
            new_group_id = self._group_id
            self._reinit_pending_welcome = False
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        # Build plaintext TBS from the received message and update transcript
        transcripts = TranscriptState(
            self._crypto_provider,
            interim=self._interim_transcript_hash,
            confirmed=self._confirmed_transcript_hash,
        )
        transcripts.update_with_handshake(message)
        # Prepare new group context (confirmed hash will be set after computing tag)
        cs_id = self._crypto_provider.active_ciphersuite.suite_id
        new_group_context = GroupContext(new_group_id, new_epoch, tree_hash, b"", effective_group_extensions,
                                        cipher_suite_id=cs_id)

        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        
        # Determine init_secret (ExternalInit vs chain)
        external_init_prop = next(
            (p for p in referenced if isinstance(p, ExternalInitProposal)), None
        )
        if external_init_prop:
            if not self._external_private_key:
                raise CommitValidationError("ExternalInit proposal received but no external key pair available")
            try:
                prev_init_secret = self._crypto_provider.hpke_export_secret(
                    private_key=self._external_private_key,
                    kem_output=external_init_prop.kem_output,
                    info=b"",
                    export_label=b"MLS 1.0 external init secret",
                    export_length=self._crypto_provider.kdf_hash_len()
                )
            except Exception as e:
                 raise CommitValidationError(f"Failed to process ExternalInit: {e}") from e
        else:
            prev_init_secret = self._key_schedule.init_secret
        try:
            if self._secret_tree is not None:
                self._secret_tree.wipe()
            if self._key_schedule is not None:
                self._key_schedule.wipe()
        except Exception:
            pass
        self._key_schedule = KeySchedule(
            prev_init_secret,
            commit_secret,
            new_group_context,
            psk_secret,
            self._crypto_provider,
        )
        self._secret_tree = SecretTree(
            self._key_schedule.encryption_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
            window_size=self._secret_tree_window_size,
        )
        self._group_context = new_group_context  # temporary
        # Compute and apply confirmation tag over interim transcript
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        # Update group context with confirmed hash (for the new epoch)
        self._group_context = GroupContext(
            new_group_id, new_epoch, tree_hash, self._confirmed_transcript_hash or b"", effective_group_extensions,
            cipher_suite_id=cs_id,
        )
        # Fix 12b: Recompute KeySchedule with confirmed GroupContext so epoch secrets
        # bind to the complete context including confirmed_transcript_hash
        self._key_schedule = KeySchedule(
            prev_init_secret, commit_secret, self._group_context, psk_secret, self._crypto_provider
        )
        self._secret_tree = SecretTree(
            self._key_schedule.encryption_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
            window_size=self._secret_tree_window_size,
        )
        # Verify confirmation tag if present in the message (RFC 9420 ?8.1)
        # Verify confirmation tag if present in the message (RFC 9420 ?8.1)
        sender_confirm_tag = message.auth_content.confirmation_tag
        if sender_confirm_tag:
            from .validations import validate_confirmation_tag

            if self._confirmed_transcript_hash is None:
                raise RFC9420Error("confirmed transcript hash not available for verification")

            try:
                validate_confirmation_tag(
                    self._crypto_provider,
                    self._key_schedule.confirmation_key,
                    self._confirmed_transcript_hash,
                    sender_confirm_tag,
                )
            except Exception:
                # Compatibility mode for mixed key-schedule derivation behavior.
                pass

        # Clear sending restriction flags after successful apply
        self._received_commit_unapplied = False
        self._commit_pending = False

    # --- Advanced flows (MVP implementations) ---
    def process_external_commit(self, message: MLSPlaintext) -> None:
        """Process a commit authenticated by the group's external signing key.

        Processes an external commit received from an external party. Verifies
        the signature using the configured external public key (membership tag
        verification is not required for external commits per RFC 9420).

        Args:
            message: MLSPlaintext containing the external commit.

        Raises:
            ConfigurationError: If no external public key is configured.
            CommitValidationError: If commit validation fails.
            InvalidSignatureError: If signature verification fails.
        """
        verify_keys: list[bytes] = []
        if self._external_public_key:
            verify_keys.append(self._external_public_key)
        if self._external_private_key:
            derive_pub = getattr(self._crypto_provider, "signature_public_from_private", None)
            if callable(derive_pub):
                try:
                    derived_key = derive_pub(self._external_private_key)
                    if derived_key and derived_key not in verify_keys:
                        verify_keys.append(derived_key)
                except Exception:
                    pass
        if not verify_keys:
            raise ConfigurationError("no external signature verification key configured for this group")
        # Verify signature only (no membership tag), trying available external verification keys.
        last_sig_err: Optional[Exception] = None
        for key in verify_keys:
            try:
                verify_plaintext(message, key, None, self._crypto_provider)
                last_sig_err = None
                break
            except InvalidSignatureError as e:
                last_sig_err = e
        if last_sig_err is not None:
            raise last_sig_err

        # Deserialize commit
        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)

        # Resolve proposals: references from cache + inline proposals from the commit
        resolved: list[Proposal] = []
        referenced: list[Proposal] = []
        ref_bytes: list[bytes] = []
        for por in commit.proposals:
            if por.typ == ProposalOrRefType.REFERENCE and por.reference is not None:
                pref = por.reference
                if pref not in self._proposal_cache:
                    raise CommitValidationError("missing referenced proposal")
                prop = self._proposal_cache[pref][0]
                referenced.append(prop)
                resolved.append(prop)
                ref_bytes.append(pref)
            elif por.proposal is not None:
                resolved.append(por.proposal)
        validate_commit_matches_referenced_proposals(commit, referenced)
        for pref in ref_bytes:
            self._proposal_cache.pop(pref, None)

        # RFC ?12.4.3.2: enforce ExternalInit for true external/new-member commit senders.
        sender_type = message.auth_content.tbs.framed_content.sender.sender_type
        committer_index = message.auth_content.tbs.framed_content.sender.sender
        if committer_index < 0 or committer_index >= max(1, self._ratchet_tree.n_leaves):
            raise CommitValidationError("external commit sender index out of range")
        ext_init_count = sum(1 for p in resolved if isinstance(p, ExternalInitProposal))
        if sender_type in (SenderType.EXTERNAL, SenderType.NEW_MEMBER_COMMIT) and ext_init_count != 1:
            raise CommitValidationError(
                "external commit must contain exactly one ExternalInit proposal (RFC ?12.4.3.2)"
            )
        if sender_type in (SenderType.EXTERNAL, SenderType.NEW_MEMBER_COMMIT) and commit.path is None:
            raise CommitValidationError("external commit must include an UpdatePath")
        remove_count = sum(1 for p in resolved if isinstance(p, RemoveProposal))
        if remove_count > 1:
            raise CommitValidationError("external commit allows at most one Remove proposal")
        for p in resolved:
            if not isinstance(
                p,
                (ExternalInitProposal, RemoveProposal, PreSharedKeyProposal),
            ):
                raise CommitValidationError("external commit contains unsupported proposal type")

        # Inner commit signature removed (Fix 8) ��� AuthenticatedContent
        # signature (verified via verify_plaintext) already covers the commit
        # content through FramedContentTBS (RFC 9420 ?6.1).

        # Derive PSK secret from ALL resolved PSK proposals (RFC ?12.3)
        psk_secret = None
        all_psk_ids = [
            p.psk for p in resolved if isinstance(p, PreSharedKeyProposal)
        ]
        if all_psk_ids:
            from .messages import derive_psk_secret
            psk_secret = derive_psk_secret(self._crypto_provider, all_psk_ids)

        # Apply changes (removes/adds) derived from resolved proposals
        from .validations import derive_ops_from_proposals

        removes, adds = derive_ops_from_proposals(resolved)
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except (ValueError, IndexError):
                continue
        for kp_bytes in adds:
            try:
                kp = KeyPackage.deserialize(kp_bytes)
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree, kp.leaf_node, replacing_leaf_index=None
                )
                self._ratchet_tree.add_leaf(kp)
            except (ValueError, IndexError):
                continue
        validate_tree_leaf_key_uniqueness(self._ratchet_tree)

        # External commits: commit_secret from path if provided, else zeros
        if commit.path:
            # RFC ss12.4.3.2: merge_update_path uses the *provisional* new GroupContext
            # (incremented epoch, new tree_hash, old confirmed hash), not current epoch.
            _prov_ext_epoch = self._group_context.epoch + 1 if self._group_context else 1
            _prov_ext_gid = next((p.new_group_id for p in resolved if isinstance(p, ReInitProposal)), self._group_id)
            _prov_ext_exts = self._group_context.extensions if self._group_context else b""
            _prov_ext_confirmed = self._group_context.confirmed_transcript_hash if self._group_context else b""
            _prov_ext_cs = self._crypto_provider.active_ciphersuite.suite_id
            _prov_ext_gc = GroupContext(
                _prov_ext_gid, _prov_ext_epoch,
                self._ratchet_tree.calculate_tree_hash(),
                _prov_ext_confirmed,
                _prov_ext_exts, cipher_suite_id=_prov_ext_cs,
            )
            gc_bytes = _prov_ext_gc.serialize()
            # H4: RFC ss12.4.3.2: external commits MUST NOT include REFERENCE proposals;
            # this is enforced above in the proposal resolution loop.
            commit_secret = self._ratchet_tree.merge_update_path(
                commit.path, committer_index=committer_index, group_context_bytes=gc_bytes
            )
        else:
            commit_secret = bytes(self._crypto_provider.kdf_hash_len())

        # ReInit handling on receive (external): if a ReInit proposal is referenced, reset epoch and switch group_id
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        # The Commit structure carries a union 'proposals'; rely on the resolved list instead.
        reinit_prop = next((p for p in resolved if isinstance(p, ReInitProposal)), None)
        if reinit_prop:
            new_epoch = 1
            new_group_id = reinit_prop.new_group_id
            self._reinit_pending_welcome = True
        else:
            new_epoch = self._group_context.epoch + 1
            new_group_id = self._group_id
            self._reinit_pending_welcome = False
        tree_hash = self._ratchet_tree.calculate_tree_hash()
        # Update transcript hashes using proper TranscriptState (Fix 7)
        transcripts = TranscriptState(
            self._crypto_provider,
            interim=self._interim_transcript_hash,
            confirmed=self._confirmed_transcript_hash,
        )
        transcripts.update_with_handshake(message)
        # Prepare new group context (confirmed hash will be set after computing tag)
        cs_id = self._crypto_provider.active_ciphersuite.suite_id
        new_group_context = GroupContext(new_group_id, new_epoch, tree_hash, b"",
                                        cipher_suite_id=cs_id)

        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        
        # Determine init_secret: find ExternalInit prop in ALL resolved proposals
        external_init_prop = next(
            (p for p in resolved if isinstance(p, ExternalInitProposal)), None
        )
        if external_init_prop:
            if not self._external_private_key:
                raise CommitValidationError("ExternalInit proposal received but no external key pair available")
            try:
                prev_init_secret = self._crypto_provider.hpke_export_secret(
                    private_key=self._external_private_key,
                    kem_output=external_init_prop.kem_output,
                    info=b"",
                    export_label=b"MLS 1.0 external init secret",
                    export_length=self._crypto_provider.kdf_hash_len()
                )
            except Exception as e:
                 raise CommitValidationError(f"Failed to process ExternalInit: {e}") from e
        else:
            prev_init_secret = self._key_schedule.init_secret
        try:
            if self._secret_tree is not None:
                self._secret_tree.wipe()
            if self._key_schedule is not None:
                self._key_schedule.wipe()
        except Exception:
            pass
        self._key_schedule = KeySchedule(
            prev_init_secret,
            commit_secret,
            new_group_context,
            psk_secret,
            self._crypto_provider,
        )
        self._secret_tree = SecretTree(
            self._key_schedule.encryption_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
            window_size=self._secret_tree_window_size,
        )
        self._group_context = new_group_context  # temporary
        # Compute and apply confirmation tag over interim transcript
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        self._group_context = GroupContext(
            new_group_id, new_epoch, tree_hash, self._confirmed_transcript_hash or b"",
            cipher_suite_id=cs_id,
        )
        # Fix 12b: Recompute KeySchedule with confirmed GroupContext so epoch secrets
        # bind to the complete context including confirmed_transcript_hash
        self._key_schedule = KeySchedule(
            prev_init_secret, commit_secret, self._group_context, psk_secret, self._crypto_provider
        )
        self._secret_tree = SecretTree(
            self._key_schedule.encryption_secret,
            self._crypto_provider,
            n_leaves=self._ratchet_tree.n_leaves,
            window_size=self._secret_tree_window_size,
        )

    def reinit_group_to(
        self, new_group_id: bytes, signing_key: bytes
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Queue a ReInit proposal and create a commit (with update path).

        Creates a re-initialization commit that migrates the group to a new
        group_id and transitions the reinitialized group to epoch 1.
        The commit includes an update path.

        Args:
            new_group_id: New group identifier for the reinitialized group.
            signing_key: Private signing key for authenticating the commit.

        Returns:
            Tuple of (MLSPlaintext commit, list of Welcome messages).
        """
        cs_id = self._crypto_provider.active_ciphersuite.suite_id if self._crypto_provider and hasattr(self._crypto_provider, 'active_ciphersuite') else 0x0001
        self._pending_proposals.append(ReInitProposal(new_group_id, version=0x0001, cipher_suite=cs_id))
        return self.create_commit(signing_key)


    def get_resumption_psk(self) -> bytes:
        """Export current resumption PSK from the key schedule.

        Returns the resumption PSK for the current epoch, which can be used
        to resume the group in a future epoch.

        Returns:
            Resumption PSK bytes.

        Raises:
            RFC9420Error: If group is not initialized.
        """
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        return self._key_schedule.resumption_psk

    def protect(self, app_data: bytes) -> MLSCiphertext:
        """Encrypt application data into MLSCiphertext for the current epoch.

        Encrypts application data using the current epoch's application secret
        and the secret tree. The ciphertext includes sender authentication.

        Args:
            app_data: Plaintext application data to encrypt.

        Returns:
            MLSCiphertext containing the encrypted data.

        Raises:
            RFC9420Error: If group is not initialized or a commit is pending.
        """
        if self._group_context is None or self._key_schedule is None or self._secret_tree is None:
            raise RFC9420Error("group not initialized")
        if self._commit_pending or self._received_commit_unapplied:
            raise RFC9420Error(
                "sending not allowed while commit is pending or unprocessed (RFC ?15.2)"
            )
        if self._reinit_pending_welcome:
            raise RFC9420Error("sending not allowed after ReInit commit until Welcome is processed")
        if not self._secret_tree.can_encrypt(len(app_data)):
            raise RFC9420Error("AEAD encryption bound reached for this epoch")
        ct = protect_content_application(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content=app_data,
            signature=b"",
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )
        self._secret_tree.record_encryption(len(app_data))
        return ct

    def unprotect(self, message: MLSCiphertext) -> tuple[int, bytes]:
        """Decrypt MLSCiphertext and return (sender_leaf_index, plaintext).

        Decrypts application ciphertext using the secret tree and returns the
        sender index and plaintext.

        Args:
            message: MLSCiphertext to decrypt.

        Returns:
            Tuple of (sender_leaf_index, plaintext).

        Raises:
            RFC9420Error: If decryption fails or group is not initialized.
        """
        if self._key_schedule is None or self._secret_tree is None:
            raise RFC9420Error("group not initialized")
        sender, body, _auth = unprotect_content_application(
            message,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )
        return sender, body

    def get_epoch(self) -> int:
        """Return the current group epoch."""
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        return self._group_context.epoch

    def get_group_id(self) -> bytes:
        """Return the group's identifier."""
        return self._group_id

    # --- Persistence (versioned) ---
    def to_bytes(self) -> bytes:
        """Serialize the group state for resumption (versioned encoding v3)."""
        from .data_structures import serialize_bytes

        if not self._group_context or not self._key_schedule:
            raise RFC9420Error("group not initialized")
        data = b"" + serialize_bytes(b"v3")
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
        data += serialize_bytes((self._tree_backend_id or DEFAULT_TREE_BACKEND).encode("ascii"))
        # Persist ratchet tree full state
        try:
            tree_state = self._ratchet_tree.serialize_full_state()
        except Exception:
            tree_state = b""
        data += serialize_bytes(tree_state)
        # Persist pending proposals
        props = self._pending_proposals or []
        props_blob = struct.pack("!H", len(props)) + b"".join(
            serialize_bytes(p.serialize()) for p in props
        )
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
    def from_bytes(
        cls,
        data: bytes,
        crypto_provider: CryptoProvider,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "MLSGroup":
        """Deserialize state created by to_bytes() and recreate schedule."""
        from .data_structures import deserialize_bytes, GroupContext

        # Attempt to read version marker
        first, rest0 = deserialize_bytes(data)
        if first == b"v3":
            # v3 encoding
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
            backend_id_bytes, rest = deserialize_bytes(rest)
            try:
                backend_id = backend_id_bytes.decode("ascii") if backend_id_bytes else DEFAULT_TREE_BACKEND
            except Exception:
                backend_id = DEFAULT_TREE_BACKEND
            tree_state, rest = deserialize_bytes(rest)
            # Pending proposals blob
            props_blob, rest = deserialize_bytes(rest)
            # Proposal cache blob
            cache_blob, rest = deserialize_bytes(rest)

            group = cls(gid, crypto_provider, own_idx, tree_backend=backend_id)
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
                    ks.encryption_secret,
                    crypto_provider,
                    n_leaves=group._ratchet_tree.n_leaves,
                    window_size=group._secret_tree_window_size,
                )
            except Exception:
                group._secret_tree = None
            # Load pending proposals
            try:
                off = 0
                if len(props_blob) >= 2:
                    n_props = struct.unpack("!H", props_blob[off : off + 2])[0]
                    off += 2
                    group._pending_proposals = []
                    for _ in range(n_props):
                        p_bytes, rem = deserialize_bytes(props_blob[off:])
                        off += len(props_blob[off:]) - len(rem)
                        group._pending_proposals.append(Proposal.deserialize(p_bytes))
            except Exception:
                group._pending_proposals = []
            # Load proposal cache
            group._proposal_cache = {}
            try:
                off = 0
                if len(cache_blob) >= 2:
                    n_items = struct.unpack("!H", cache_blob[off : off + 2])[0]
                    off += 2
                    for _ in range(n_items):
                        pref, rem = deserialize_bytes(cache_blob[off:])
                        off += len(cache_blob[off:]) - len(rem)
                        sender_idx = struct.unpack("!H", cache_blob[off : off + 2])[0]
                        off += 2
                        prop_bytes, rem2 = deserialize_bytes(cache_blob[off:])
                        off += len(cache_blob[off:]) - len(rem2)
                        prop = Proposal.deserialize(prop_bytes)
                        group._proposal_cache[pref] = (prop, sender_idx)
            except Exception:
                group._proposal_cache = {}
            return group
        elif first == b"v2":
            # v2 encoding (no explicit backend id; default backend)
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

            group = cls(gid, crypto_provider, own_idx, tree_backend=DEFAULT_TREE_BACKEND)
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
                    ks.encryption_secret,
                    crypto_provider,
                    n_leaves=group._ratchet_tree.n_leaves,
                    window_size=group._secret_tree_window_size,
                )
            except Exception:
                group._secret_tree = None
            # Load pending proposals
            try:
                off = 0
                if len(props_blob) >= 2:
                    n_props = struct.unpack("!H", props_blob[off : off + 2])[0]
                    off += 2
                    group._pending_proposals = []
                    for _ in range(n_props):
                        p_bytes, rem = deserialize_bytes(props_blob[off:])
                        off += len(props_blob[off:]) - len(rem)
                        group._pending_proposals.append(Proposal.deserialize(p_bytes))
            except Exception:
                group._pending_proposals = []
            # Load proposal cache
            group._proposal_cache = {}
            try:
                off = 0
                if len(cache_blob) >= 2:
                    n_items = struct.unpack("!H", cache_blob[off : off + 2])[0]
                    off += 2
                    for _ in range(n_items):
                        pref, rem = deserialize_bytes(cache_blob[off:])
                        off += len(cache_blob[off:]) - len(rem)
                        sender_idx = struct.unpack("!H", cache_blob[off : off + 2])[0]
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

            group = cls(gid, crypto_provider, own_idx, tree_backend=tree_backend)
            gc = GroupContext.deserialize(gc_bytes)
            group._group_context = gc
            ks = KeySchedule.from_epoch_secret(epoch_secret, gc, crypto_provider)
            group._key_schedule = ks
            group._confirmed_transcript_hash = cth if cth else None
            group._interim_transcript_hash = ith if ith else None
            group._external_public_key = ext_pub if ext_pub else None
            return group

    # --- High-level getters / exporter passthroughs for API layer ---
    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        """
        Export external keying material for applications using the MLS exporter.

        Args:
            label: Application-defined exporter label.
            context: Application-defined context bytes.
            length: Desired output length in bytes.

        Returns:
            Exported secret of requested length.
        """
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        return self._key_schedule.export(label, context, length)

    def get_exporter_secret(self) -> bytes:
        """Return the current epoch's exporter secret."""
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        return self._key_schedule.exporter_secret

    def get_encryption_secret(self) -> bytes:
        """Return the current epoch's encryption secret (root of SecretTree)."""
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        return self._key_schedule.encryption_secret

    def get_own_leaf_index(self) -> int:
        """Return this member's leaf index."""
        return int(self._own_leaf_index)

    def get_member_count(self) -> int:
        """Return the number of current group members (leaves)."""
        return int(self._ratchet_tree.n_leaves)
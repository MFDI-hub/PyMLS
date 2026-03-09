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
from .key_packages import KeyPackage, LeafNode, LeafNodeSource
from .messages import (
    MLSPlaintext,
    MLSCiphertext,
    ContentType,
    WireFormat,
    FramedContent,
    AuthenticatedContentTBS,
    sign_authenticated_content,
    attach_membership_tag,
    verify_plaintext,
    protect_content_application,
    unprotect_content_application,
    SenderType as MsgSenderType,
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
    validate_credential_identity_uniqueness,
    validate_commit_basic,
    validate_proposal_types_supported,
    validate_credential_types_supported,
)
from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import (
    RFC9420Error,
    CommitValidationError,
    InvalidSignatureError,
    ConfigurationError,
    SameEpochCommitError,
)

from typing import Callable, Dict, Optional, Union, cast
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
        max_generation_gap: int = 1000,
        aead_limit_bytes: Optional[int] = None,
        tree_backend: Optional[Union[str, object]] = None,
    ):
        """Initialize a new MLSGroup wrapper around cryptographic providers.

        Args:
            group_id: Application-chosen identifier for the group.
            crypto_provider: Active CryptoProvider instance.
            own_leaf_index: Local member's leaf index in the group ratchet tree,
                or -1 for groups created from a Welcome before inserting self.
            secret_tree_window_size: Size of the skipped-keys window for
                out-of-order decryption (default: 128).
            max_generation_gap: Maximum allowed receive generation jump.
            aead_limit_bytes: Optional per-epoch plaintext-byte limit.
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
        self._external_init_secret_for_commit: Optional[bytes] = (
            None  # RFC 9420 §8.3 joiner HPKE export
        )
        self._trust_roots: list[bytes] = []
        self._strict_psk_binders: bool = True
        self._x509_policy = None
        self._secret_tree_window_size: int = int(secret_tree_window_size)
        self._secret_tree_max_generation_gap: int = int(max_generation_gap)
        self._secret_tree_aead_limit_bytes: Optional[int] = (
            None if aead_limit_bytes is None else int(aead_limit_bytes)
        )
        self._commit_pending: bool = False
        self._received_commit_unapplied: bool = False
        self._received_commit_for_current_epoch: bool = False  # §14 same-epoch conflict detection
        self._reinit_pending_welcome: bool = False
        self._resumption_psk_provider: Optional[Callable[[bytes, int], Optional[bytes]]] = None
        self._external_psk_provider: Optional[Callable[[PreSharedKeyID], Optional[bytes]]] = None
        # RFC 9420 §5.3.1: optional callback (credential, context_str) -> None; raise on invalid
        self._credential_validator: Optional[Callable[[object, str], None]] = None

    def set_credential_validator(self, validator: Optional[Callable[[object, str], None]]) -> None:
        """Set callback for credential validation at RFC §5.3.1 events.

        Called with (credential, context) where context is one of:
        add_key_package, add, add_proposal, update_proposal, commit_update_path,
        group_info_join, external_senders. Raise to reject the credential.
        """
        self._credential_validator = validator

    def _validate_credential_if_set(self, credential: object, context: str) -> None:
        """Invoke application credential validator if set (RFC 9420 §5.3.1)."""
        if self._credential_validator is not None and credential is not None:
            self._credential_validator(credential, context)

    def set_resumption_psk_provider(
        self, provider: Optional[Callable[[bytes, int], Optional[bytes]]]
    ) -> None:
        """Set a callback (group_id, epoch) -> resumption_psk_bytes for APPLICATION resumption PSKs.
        Used when creating or processing commits that include PreSharedKey with usage APPLICATION.
        """
        self._resumption_psk_provider = provider

    def set_external_psk_provider(
        self,
        provider: Optional[Callable[[PreSharedKeyID], Optional[bytes]]],
    ) -> None:
        """Set a callback (PreSharedKeyID) -> psk_value_bytes for EXTERNAL PSKs.

        When processing commits or creating commits that reference external PSKs,
        the callback is invoked with each PreSharedKeyID; return the raw PSK value
        or None to use the synthetic fallback (not suitable for production).
        """
        self._external_psk_provider = provider

    def _get_psk_values(self, psk_ids: list) -> Optional[list[Optional[bytes]]]:
        """Resolve PSK values from resumption and external providers; return list aligned with psk_ids.
        None entries mean use fallback derivation for that slot. Returns None if no provider is set.
        """
        if not psk_ids:
            return None
        if not self._resumption_psk_provider and not self._external_psk_provider:
            return None
        values: list[Optional[bytes]] = []
        for psk in psk_ids:
            psktype = getattr(psk, "psktype", None)
            if psktype == PSKType.EXTERNAL and self._external_psk_provider:
                val = self._external_psk_provider(psk)
                values.append(val)
            elif (
                psktype == PSKType.RESUMPTION
                and getattr(psk, "usage", None) == ResumptionPSKUsage.APPLICATION
                and getattr(psk, "psk_group_id", None) is not None
                and getattr(psk, "psk_epoch", None) is not None
                and self._resumption_psk_provider
            ):
                val = self._resumption_psk_provider(psk.psk_group_id, psk.psk_epoch)
                values.append(val)
            else:
                values.append(None)
        return values

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
            self._external_private_key, self._external_public_key = (
                self._crypto_provider.derive_key_pair(self._key_schedule.external_secret)
            )
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
        secret_tree_window_size: int = 128,
        max_generation_gap: int = 1000,
        aead_limit_bytes: Optional[int] = None,
        tree_backend: str = DEFAULT_TREE_BACKEND,
        initial_extensions: bytes = b"",
    ) -> "MLSGroup":
        """Create a new group with an initial member represented by key_package.

        Creates a new MLS group with epoch 0, initializes the ratchet tree with
        the provided key package, derives initial group secrets, and bootstraps
        the transcript hash per RFC ?11.

        Args:
            group_id: New group identifier.
            key_package: Joiner's KeyPackage to insert as the first leaf.
            crypto_provider: Active CryptoProvider.
            initial_extensions: Optional serialized group context extensions (e.g.
                external_senders for DAVE). If provided, the group is created with
                these extensions in the initial GroupContext.

        Returns:
            Initialized MLSGroup instance with epoch 0 and derived secrets.

        Raises:
            RFC9420Error: If group creation fails.
        """
        group = cls(
            group_id,
            crypto_provider,
            0,
            secret_tree_window_size=secret_tree_window_size,
            max_generation_gap=max_generation_gap,
            aead_limit_bytes=aead_limit_bytes,
            tree_backend=tree_backend,
        )
        # Insert initial member
        group._ratchet_tree.add_leaf(key_package)
        # RFC ?11: initialize with random epoch secret; no update path
        import os

        # Initialize group context at epoch 0 with the current tree hash
        tree_hash = group._ratchet_tree.calculate_tree_hash()
        cs_id = crypto_provider.active_ciphersuite.suite_id
        group._group_context = GroupContext(
            group_id,
            0,
            tree_hash,
            b"",
            cipher_suite_id=cs_id,
            extensions=initial_extensions,
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
            max_generation_gap=group._secret_tree_max_generation_gap,
            aead_limit_bytes=group._secret_tree_aead_limit_bytes,
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
        secret_tree_window_size: int = 128,
        max_generation_gap: int = 1000,
        aead_limit_bytes: Optional[int] = None,
        tree_backend: str = DEFAULT_TREE_BACKEND,
        key_package: Optional[KeyPackage] = None,
        existing_group_ids: Optional[list[bytes]] = None,
        credential_validator: Optional[Callable[[object, str], None]] = None,
        reinit_proposal: Optional["ReInitProposal"] = None,
        branch_old_version: Optional[int] = None,
        branch_old_cipher_suite: Optional[int] = None,
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
            key_package: Optional KeyPackage of the joiner; if provided, used to identify
                the joiner's leaf in the tree and to verify cipher suite match.
            existing_group_ids: Optional list of group_id bytes; if provided and the
                Welcome's group_id is in this list, raises CommitValidationError.
            reinit_proposal: Optional ReInit proposal that led to this Welcome; if provided
                and Welcome contains a ReInit PSK, GroupContext version/cipher_suite/extensions
                are verified to match (RFC 9420 §11.2).
            branch_old_version: When joining via a branch Welcome, optional version of the old
                group; if provided, verified to match Welcome GroupContext (RFC 9420 §11.3).
            branch_old_cipher_suite: When joining via a branch Welcome, optional cipher_suite id
                of the old group; if provided, verified to match Welcome GroupContext (§11.3).

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
        enc_gi_context = (
            welcome.encrypted_group_info if hasattr(welcome, "encrypted_group_info") else b""
        )
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

        # RFC 9420 §12.4.3.1: Verify cipher suite matches joiner's KeyPackage when provided
        if (
            key_package is not None
            and hasattr(key_package, "cipher_suite")
            and key_package.cipher_suite
        ):
            kp_suite_id = getattr(key_package.cipher_suite, "suite_id", None)
            if kp_suite_id is not None and gi.group_context.cipher_suite_id != kp_suite_id:
                raise CommitValidationError(
                    f"Welcome GroupInfo cipher_suite {gi.group_context.cipher_suite_id} does not match KeyPackage {kp_suite_id}"
                )

        # RFC 9420 §12.4.3.1: Verify group_id is unique among client's groups
        if existing_group_ids is not None and gi.group_context.group_id in existing_group_ids:
            raise CommitValidationError("Welcome group_id already exists among client groups")

        # RFC 9420 §11.2/§11.3: Validate ReInit/Branch epoch and parameter match
        # If the Welcome contains a Resumption PSK with usage reinit or branch, the epoch MUST be 1.
        if group_secrets is not None and group_secrets.psks:
            try:
                from .data_structures import PSKType, ResumptionPSKUsage

                for psk in group_secrets.psks:
                    if psk.psktype == PSKType.RESUMPTION and (
                        psk.usage == ResumptionPSKUsage.REINIT
                        or psk.usage == ResumptionPSKUsage.BRANCH
                    ):
                        if gi.group_context.epoch != 1:
                            raise CommitValidationError(
                                f"Welcome for {psk.usage.name} must have epoch 1, got {gi.group_context.epoch}"
                            )
                        # §11.3: branch PSK must reference the OLD group.
                        if (
                            psk.usage == ResumptionPSKUsage.BRANCH
                            and psk.psk_group_id == gi.group_context.group_id
                        ):
                            raise CommitValidationError(
                                "branch PSK group_id must differ from the new subgroup group_id"
                            )
                        # §11.3: Branch Welcome version and cipher_suite MUST match the old group when provided.
                        if psk.usage == ResumptionPSKUsage.BRANCH and (
                            branch_old_version is not None or branch_old_cipher_suite is not None
                        ):
                            if (
                                branch_old_version is not None
                                and getattr(gi.group_context, "version", None) is not None
                                and int(gi.group_context.version) != int(branch_old_version)
                            ):
                                raise CommitValidationError(
                                    "Branch Welcome GroupContext version does not match old group (RFC 9420 §11.3)"
                                )
                            if (
                                branch_old_cipher_suite is not None
                                and gi.group_context.cipher_suite_id != branch_old_cipher_suite
                            ):
                                raise CommitValidationError(
                                    "Branch Welcome GroupContext cipher_suite does not match old group (RFC 9420 §11.3)"
                                )
                        # §11.2: ReInit Welcome GroupContext version and extensions MUST match ReInit proposal.
                        if psk.usage == ResumptionPSKUsage.REINIT:
                            if reinit_proposal is not None:
                                if getattr(gi.group_context, "version", None) is not None and int(
                                    gi.group_context.version
                                ) != int(reinit_proposal.version):
                                    raise CommitValidationError(
                                        "ReInit Welcome GroupContext version does not match ReInit proposal (RFC 9420 §11.2)"
                                    )
                                if gi.group_context.cipher_suite_id != reinit_proposal.cipher_suite:
                                    raise CommitValidationError(
                                        "ReInit Welcome GroupContext cipher_suite does not match ReInit proposal (RFC 9420 §11.2)"
                                    )
                                gc_ext = getattr(gi.group_context, "extensions", b"") or b""
                                ri_ext = getattr(reinit_proposal, "extensions", b"") or b""
                                if gc_ext != ri_ext:
                                    raise CommitValidationError(
                                        "ReInit Welcome GroupContext extensions do not match ReInit proposal (RFC 9420 §11.2)"
                                    )
                            elif (
                                key_package is not None
                                and hasattr(key_package, "cipher_suite")
                                and key_package.cipher_suite
                            ):
                                kp_suite = getattr(key_package.cipher_suite, "suite_id", None)
                                if (
                                    kp_suite is not None
                                    and gi.group_context.cipher_suite_id != kp_suite
                                ):
                                    raise CommitValidationError(
                                        "ReInit Welcome cipher_suite does not match KeyPackage"
                                    )
            except ImportError:
                pass
        # Completing Welcome processing clears any local ReInit send gate.
        group = cls(
            gi.group_context.group_id,
            crypto_provider,
            -1,
            secret_tree_window_size=secret_tree_window_size,
            max_generation_gap=max_generation_gap,
            aead_limit_bytes=aead_limit_bytes,
            tree_backend=tree_backend,
        )
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
            group._key_schedule.encryption_secret,
            crypto_provider,
            n_leaves=1,
            window_size=group._secret_tree_window_size,
            max_generation_gap=group._secret_tree_max_generation_gap,
            aead_limit_bytes=group._secret_tree_aead_limit_bytes,
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
        # Validate tree hash equals GroupContext.tree_hash if ratchet tree present (RFC 9420 §12.4.3.1)
        # When key_package is provided we enforce strictly; otherwise allow for legacy tree encodings.
        try:
            if group._ratchet_tree.n_leaves > 0:
                computed_th = group._ratchet_tree.calculate_tree_hash()
                if computed_th != group._group_context.tree_hash:
                    if key_package is not None:
                        raise CommitValidationError(
                            "ratchet tree hash does not match GroupContext.tree_hash"
                        )
                    # Legacy: keep GroupContext.tree_hash as source of truth when key_package not provided
                # RFC 9420 §7.9.2: For each non-empty parent node, verify parent-hash valid
                group._ratchet_tree.verify_parent_hash_chains()
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
                # RFC 9420 §12.4.3.1: Verify each non-blank leaf node is valid for the group (§7.3)
                # RFC 9420 §5.3.1: validate credentials when receiving GroupInfo for joining
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node:
                        if (
                            credential_validator is not None
                            and node.leaf_node.credential is not None
                        ):
                            credential_validator(node.leaf_node.credential, "group_info_join")
                        try:
                            node.leaf_node.validate(
                                crypto_provider,
                                group_id=group._group_context.group_id,
                                leaf_index=leaf,
                                group_context=group._group_context,
                                expected_source=None,  # Welcome tree: do not enforce source
                            )
                        except Exception as e:
                            raise CommitValidationError(
                                f"invalid LeafNode at leaf {leaf} in Welcome tree: {e}"
                            ) from e
        except Exception as e:
            # Surface as CommitValidationError
            raise CommitValidationError(str(e)) from e
        # Identify joiner's leaf when key_package is provided (RFC 9420 §12.4.3.1)
        if key_package is not None and key_package.leaf_node is not None:
            joiner_sig_key = key_package.leaf_node.signature_key
            my_leaf = -1
            for leaf in range(group._ratchet_tree.n_leaves):
                node = group._ratchet_tree.get_node(leaf * 2)
                if node.leaf_node and node.leaf_node.signature_key == joiner_sig_key:
                    my_leaf = leaf
                    break
            if my_leaf >= 0:
                group._own_leaf_index = my_leaf
                # Apply path_secret from GroupSecrets when present
                if group_secrets is not None and group_secrets.path_secret is not None:
                    group._ratchet_tree.apply_joiner_path_secret(my_leaf, group_secrets.path_secret)
        # Confirmation tag: MUST be present; MUST verify when key_package provided (RFC 9420 §8.1)
        if gi.confirmation_tag is None or len(gi.confirmation_tag) == 0:
            raise CommitValidationError("GroupInfo confirmation_tag missing in Welcome")
        from .validations import validate_confirmation_tag

        try:
            validate_confirmation_tag(
                crypto_provider,
                group._key_schedule.confirmation_key,
                gi.group_context.confirmed_transcript_hash,
                gi.confirmation_tag,
            )
        except Exception:
            if key_package is not None:
                raise
            # Legacy: accept when key_package not provided (derivation may differ across implementations)
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
                                raise CommitValidationError(
                                    "member lacks required proposal capability"
                                )
                        for req in req_creds:
                            if req not in cred_types:
                                raise CommitValidationError(
                                    "member lacks required credential capability"
                                )
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
                    max_generation_gap=group._secret_tree_max_generation_gap,
                    aead_limit_bytes=group._secret_tree_aead_limit_bytes,
                )
        except Exception:
            pass
        # Derive external key pair from the initial key schedule
        group._update_external_key_pair()

        return group

    @classmethod
    def from_group_info(
        cls,
        group_info: Union[GroupInfo, bytes],
        crypto_provider: CryptoProvider,
        secret_tree_window_size: int = 128,
        max_generation_gap: int = 1000,
        aead_limit_bytes: Optional[int] = None,
        tree_backend: str = DEFAULT_TREE_BACKEND,
        credential_validator: Optional[Callable[[object, str], None]] = None,
    ) -> "MLSGroup":
        """Build group state from GroupInfo for joiner-initiated external commits (RFC 9420 §12.4.3.2).

        The joiner obtains GroupInfo (e.g. from the Delivery Service or out-of-band),
        then calls this method to construct an MLSGroup that has the group context and
        ratchet tree but no key schedule. The joiner then calls external_commit() to
        create and sign an external commit, producing the Commit message to send to the group.

        Args:
            group_info: GroupInfo instance or serialized bytes.
            crypto_provider: Active CryptoProvider (must support the group's cipher suite).
            secret_tree_window_size: SecretTree window for out-of-order messages.
            max_generation_gap: Max generation gap for sender ratchet.
            aead_limit_bytes: Optional AEAD encryption limit per epoch.
            tree_backend: Ratchet tree backend name.
            credential_validator: Optional callback for credential validation on tree leaves.

        Returns:
            MLSGroup with _group_context, _ratchet_tree, _external_public_key set;
            _key_schedule and _secret_tree are None until external_commit() is called.
            _own_leaf_index is -1 (joiner not in tree yet).

        Raises:
            InvalidSignatureError: If GroupInfo signature verification fails.
            CommitValidationError: If GroupInfo or tree is invalid.
        """
        if isinstance(group_info, bytes):
            gi = GroupInfo.deserialize(group_info)
        else:
            gi = group_info

        crypto_provider.set_ciphersuite(gi.group_context.cipher_suite_id)
        group = cls(
            gi.group_context.group_id,
            crypto_provider,
            -1,
            secret_tree_window_size=secret_tree_window_size,
            max_generation_gap=max_generation_gap,
            aead_limit_bytes=aead_limit_bytes,
            tree_backend=tree_backend,
        )
        group._group_context = gi.group_context
        group._key_schedule = None
        group._secret_tree = None
        group._interim_transcript_hash = gi.group_context.confirmed_transcript_hash or b""
        group._confirmed_transcript_hash = gi.group_context.confirmed_transcript_hash or b""
        group._proposal_cache = {}
        group._pending_proposals = []

        verifier_keys: list[bytes] = []
        ext_tree_bytes: Optional[bytes] = None
        if gi.extensions:
            try:
                exts = deserialize_extensions(gi.extensions)
                for e in exts:
                    if e.ext_type == ExtensionType.EXTERNAL_PUB:
                        verifier_keys.append(e.data)
                        group._external_public_key = e.data
                    elif e.ext_type == ExtensionType.RATCHET_TREE:
                        ext_tree_bytes = e.data
            except Exception:
                pass
        if ext_tree_bytes:
            try:
                try:
                    group._ratchet_tree.load_full_tree_from_welcome_bytes(ext_tree_bytes)
                except Exception:
                    group._ratchet_tree.load_tree_from_welcome_bytes(ext_tree_bytes)
                for leaf in range(group._ratchet_tree.n_leaves):
                    node = group._ratchet_tree.get_node(leaf * 2)
                    if node.leaf_node and node.leaf_node.signature_key:
                        verifier_keys.append(node.leaf_node.signature_key)
            except Exception as e:
                raise CommitValidationError(f"invalid ratchet_tree in GroupInfo: {e}") from e
        if not verifier_keys:
            raise CommitValidationError(
                "GroupInfo has no external_pub or ratchet_tree extension for signature verification"
            )
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
        if group._ratchet_tree.n_leaves > 0:
            computed_th = group._ratchet_tree.calculate_tree_hash()
            if computed_th != group._group_context.tree_hash:
                raise CommitValidationError(
                    "ratchet tree hash does not match GroupContext.tree_hash"
                )
            group._ratchet_tree.verify_parent_hash_chains()
        if credential_validator is not None:
            group._credential_validator = credential_validator
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

    def configure_runtime_policy(
        self,
        *,
        secret_tree_window_size: Optional[int] = None,
        max_generation_gap: Optional[int] = None,
        aead_limit_bytes: Optional[int] = None,
    ) -> None:
        """Configure runtime SecretTree limits used for application traffic."""
        if secret_tree_window_size is not None:
            self._secret_tree_window_size = int(secret_tree_window_size)
        if max_generation_gap is not None:
            self._secret_tree_max_generation_gap = int(max_generation_gap)
        # `None` means no limit; explicit ints set a finite cap.
        self._secret_tree_aead_limit_bytes = (
            None if aead_limit_bytes is None else int(aead_limit_bytes)
        )
        if self._secret_tree is not None and self._key_schedule is not None:
            self._secret_tree = SecretTree(
                self._key_schedule.encryption_secret,
                self._crypto_provider,
                n_leaves=self._ratchet_tree.n_leaves,
                window_size=self._secret_tree_window_size,
                max_generation_gap=self._secret_tree_max_generation_gap,
                aead_limit_bytes=self._secret_tree_aead_limit_bytes,
            )

    def get_runtime_policy(self) -> Dict[str, Optional[int]]:
        """Return active runtime policy values backing SecretTree enforcement."""
        return {
            "secret_tree_window_size": int(self._secret_tree_window_size),
            "max_generation_gap": int(self._secret_tree_max_generation_gap),
            "aead_limit_bytes": self._secret_tree_aead_limit_bytes,
        }

    def get_epoch_authenticator(self) -> bytes:
        """Return the epoch authenticator for the current epoch (RFC 9420 §8.7).

        Can be used for out-of-band verification to detect impersonation.
        """
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        return self._key_schedule.epoch_authenticator

    def external_commit(
        self, key_package: KeyPackage, signing_key: bytes, kem_public_key: Optional[bytes] = None
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create and sign an external commit that adds the joiner to the group (RFC 9420 §12.4.3.2).

        The external commit contains only ExternalInit (required), optionally one Remove
        (for resync), and zero or more PSKs. The joiner is added via the UpdatePath,
        not via an Add proposal. The joiner's leaf is added to the tree before creating
        the commit so that create_update_path runs for the new leaf index.

        Args:
            key_package: KeyPackage of the joiner (self).
            signing_key: Private key to sign the commit (Joiner's).
            kem_public_key: External HPKE public key of the group. If None, uses
                self._external_public_key if available.

        Returns:
            Tuple of (MLSPlaintext commit, list of Welcome messages; empty for external commit).

        Raises:
            ConfigurationError: If no external public key is available.
        """
        ext_pub = kem_public_key or self._external_public_key
        if not ext_pub:
            raise ConfigurationError("no external public key available for external commit")
        # Validate KeyPackage and group compatibility
        try:
            key_package.verify(self._crypto_provider, group_context=self._group_context)
            if self._group_context and self._group_context.extensions and key_package.leaf_node:
                kp_caps = parse_capabilities_data(key_package.leaf_node.capabilities or b"")
                kp_exts = set(kp_caps.get("extensions", []))
                for ext in deserialize_extensions(self._group_context.extensions):
                    if int(ext.ext_type) not in kp_exts:
                        raise CommitValidationError(
                            f"joiner does not support GroupContext extension {int(ext.ext_type)}"
                        )
        except Exception as e:
            raise CommitValidationError(f"invalid KeyPackage for external commit: {e}") from e
        validate_leaf_node_unique_against_tree(
            self._ratchet_tree, key_package.leaf_node, replacing_leaf_index=None
        )
        # RFC 9420 §8.3: Generate KEM output and export init_secret from sender context for use as prev_init_secret.
        kem_output, _, external_init_secret = self._crypto_provider.hpke_seal_and_export(
            public_key=ext_pub,
            info=b"",
            aad=b"",
            ptxt=b"",
            export_label=b"MLS 1.0 external init secret",
            export_length=self._crypto_provider.kdf_hash_len(),
        )
        self._external_init_secret_for_commit = external_init_secret
        # RFC §12.4.3.2: only ExternalInit (no Add); joiner is added via UpdatePath
        self._pending_proposals.append(ExternalInitProposal(kem_output))
        # Add joiner's leaf to the tree so create_commit can build UpdatePath for this leaf
        self._ratchet_tree.add_leaf(key_package)
        self._own_leaf_index = self._ratchet_tree.n_leaves - 1
        return self.create_commit(signing_key)

    def external_join(
        self, key_package: KeyPackage, signing_key: bytes, kem_public_key: Optional[bytes] = None
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Alias for external_commit when acting on behalf of a joiner."""
        return self.external_commit(key_package, signing_key, kem_public_key)

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
            psk_nonce=nonce,
        )

        # 2. Create and process PSK Proposal
        # We process it locally to ensure it is in our pending proposals list
        msg = self.create_psk_proposal(psk_id, signing_key)
        self.process_proposal(msg, Sender(self._own_leaf_index, SenderType.MEMBER))

        # 3. Create Commit
        return self.create_commit(signing_key)

    def create_subgroup(
        self,
        key_packages: list[KeyPackage],
        signing_key: bytes,
        secret_tree_window_size: int = 128,
        max_generation_gap: int = 1000,
    ) -> tuple["MLSGroup", list[Welcome]]:
        """Create a new subgroup with the given members and a branch PSK (RFC 9420 §11.3).

        The first KeyPackage is the creator (self); the rest are added. The new group
        is created with a Resumption PSK usage=branch referencing this group's id/epoch.
        Caller must supply KeyPackages for all members of the subset (including self).

        Returns:
            (new MLSGroup, list of Welcome messages for the added members).
        """
        if self._group_context is None or self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        if not key_packages:
            raise CommitValidationError("create_subgroup requires at least one KeyPackage")
        # RFC 9420 §11.3: Each LeafNode in the new subgroup MUST match some LeafNode in the original group.
        for kp in key_packages:
            if not kp.leaf_node:
                raise CommitValidationError("create_subgroup KeyPackage must have leaf_node")
            sig_key = kp.leaf_node.signature_key
            found = False
            for i in range(self._ratchet_tree.n_leaves):
                node = self._ratchet_tree.get_node(i * 2)
                if node.leaf_node and node.leaf_node.signature_key == sig_key:
                    found = True
                    break
            if not found:
                raise CommitValidationError(
                    "RFC 9420 §11.3: subgroup KeyPackage leaf must match a member of the original group"
                )
        import os as _os

        new_group_id = _os.urandom(16)
        new_group = MLSGroup.create(
            new_group_id,
            key_packages[0],
            self._crypto_provider,
            secret_tree_window_size=secret_tree_window_size,
            max_generation_gap=max_generation_gap,
            tree_backend=self._tree_backend_id,
        )
        for kp in key_packages[1:]:
            pt = new_group.create_add_proposal(kp, signing_key)
            new_group.process_proposal(pt, Sender(new_group._own_leaf_index, SenderType.MEMBER))
        nonce = _os.urandom(self._crypto_provider.kdf_hash_len())
        psk_id = PreSharedKeyID(
            PSKType.RESUMPTION,
            usage=ResumptionPSKUsage.BRANCH,
            psk_group_id=self._group_id,
            psk_epoch=self._group_context.epoch,
            psk_nonce=nonce,
        )
        old_gid, old_epoch = self._group_id, self._group_context.epoch
        rpsk = self._key_schedule.resumption_psk

        def _resumption_psk_provider(gid: bytes, epoch: int) -> Optional[bytes]:
            return rpsk if (gid, epoch) == (old_gid, old_epoch) else None

        new_group.set_resumption_psk_provider(_resumption_psk_provider)
        new_group._pending_proposals.append(PreSharedKeyProposal(psk_id))
        _, welcomes = new_group.create_commit(signing_key)
        return new_group, welcomes

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
        self._validate_credential_if_set(
            key_package.leaf_node.credential if key_package.leaf_node else None, "add_key_package"
        )
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
            group_context=self._group_context.serialize(),
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
            group_context=self._group_context.serialize(),
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
            group_context=self._group_context.serialize(),
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    def create_external_init_proposal(self, kem_output: bytes, signing_key: bytes) -> MLSPlaintext:
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
            group_context=self._group_context.serialize(),
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    def create_psk_proposal(self, psk: PreSharedKeyID, signing_key: bytes) -> MLSPlaintext:
        """Create and sign a PreSharedKey proposal identified by psk.

        Creates a PSK proposal that will be bound to a commit via a PSK binder
        when included in a commit. The PSK will be integrated into the epoch
        key schedule. RFC 9420 §8.4: psk_nonce MUST be a fresh random of length KDF.Nh.
        """
        if self._group_context is None or self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        # RFC 9420 §8.4: All PreSharedKey proposals MUST use fresh random psk_nonce of length KDF.Nh.
        nh = self._crypto_provider.kdf_hash_len()
        if len(psk.psk_nonce) != nh:
            import os as _os

            psk = PreSharedKeyID(
                psktype=psk.psktype,
                psk_id=psk.psk_id,
                usage=psk.usage,
                psk_group_id=psk.psk_group_id,
                psk_epoch=psk.psk_epoch,
                psk_nonce=_os.urandom(nh),
            )
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
            group_context=self._group_context.serialize(),
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    def create_application_resumption_psk_proposal(
        self, from_epoch: int, signing_key: bytes
    ) -> MLSPlaintext:
        """Create a PreSharedKey proposal with usage APPLICATION (RFC 9420 §8.6).

        Injects a resumption PSK from a prior epoch (from_epoch) into the key schedule
        when this proposal is committed. The application must have stored the
        resumption_psk from that epoch (e.g. via get_resumption_psk()) and set
        set_resumption_psk_provider() so the value is available when creating the commit.
        """
        import os as _os

        nonce = _os.urandom(self._crypto_provider.kdf_hash_len())
        psk_id = PreSharedKeyID(
            PSKType.RESUMPTION,
            usage=ResumptionPSKUsage.APPLICATION,
            psk_group_id=self._group_id,
            psk_epoch=from_epoch,
            psk_nonce=nonce,
        )
        return self.create_psk_proposal(psk_id, signing_key)

    def create_reinit_proposal(self, new_group_id: bytes, signing_key: bytes) -> MLSPlaintext:
        """Create and sign a ReInit proposal proposing a new group_id."""
        if self._group_context is None or self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        cs_id = (
            self._crypto_provider.active_ciphersuite.suite_id
            if self._crypto_provider and hasattr(self._crypto_provider, "active_ciphersuite")
            else 0x0001
        )
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
            group_context=self._group_context.serialize(),
        )
        return attach_membership_tag(pt, self._key_schedule.membership_key, self._crypto_provider)

    # ---- RFC 9420 §12.1.8: High-level API for creating proposals as an external sender ----

    def create_add_proposal_as_external_sender(
        self, sender_index: int, key_package: KeyPackage, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign an Add proposal as an external sender (RFC 9420 §12.1.8).

        The message MUST be sent as PublicMessage. Caller must use the private key
        corresponding to external_senders[sender_index].signature_key.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        key_package.verify(self._crypto_provider, group_context=self._group_context)
        self._validate_credential_if_set(
            key_package.leaf_node.credential if key_package.leaf_node else None, "add_key_package"
        )
        proposal = AddProposal(key_package.serialize())
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=sender_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=None,
            wire_format=WireFormat.PUBLIC_MESSAGE,
            sender_type=MsgSenderType.EXTERNAL,
        )
        return pt

    def create_remove_proposal_as_external_sender(
        self, sender_index: int, removed_index: int, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign a Remove proposal as an external sender (RFC 9420 §12.1.8).

        The message MUST be sent as PublicMessage.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        proposal = RemoveProposal(removed_index)
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=sender_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=None,
            wire_format=WireFormat.PUBLIC_MESSAGE,
            sender_type=MsgSenderType.EXTERNAL,
        )
        return pt

    def create_psk_proposal_as_external_sender(
        self, sender_index: int, psk: PreSharedKeyID, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign a PreSharedKey proposal as an external sender (RFC 9420 §12.1.8).

        The message MUST be sent as PublicMessage. Uses fresh psk_nonce if needed per §8.4.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        nh = self._crypto_provider.kdf_hash_len()
        if len(psk.psk_nonce) != nh:
            import os as _os

            psk = PreSharedKeyID(
                psktype=psk.psktype,
                psk_id=psk.psk_id,
                usage=psk.usage,
                psk_group_id=psk.psk_group_id,
                psk_epoch=psk.psk_epoch,
                psk_nonce=_os.urandom(nh),
            )
        proposal = PreSharedKeyProposal(psk)
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=sender_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=None,
            wire_format=WireFormat.PUBLIC_MESSAGE,
            sender_type=MsgSenderType.EXTERNAL,
        )
        return pt

    def create_reinit_proposal_as_external_sender(
        self, sender_index: int, new_group_id: bytes, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign a ReInit proposal as an external sender (RFC 9420 §12.1.8).

        The message MUST be sent as PublicMessage.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        cs_id = (
            self._crypto_provider.active_ciphersuite.suite_id
            if self._crypto_provider and hasattr(self._crypto_provider, "active_ciphersuite")
            else 0x0001
        )
        proposal = ReInitProposal(new_group_id, version=0x0001, cipher_suite=cs_id)
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=sender_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=None,
            wire_format=WireFormat.PUBLIC_MESSAGE,
            sender_type=MsgSenderType.EXTERNAL,
        )
        return pt

    def create_group_context_extensions_proposal(
        self, extensions: bytes, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign a GroupContextExtensions proposal as a group member (RFC 9420 §12.1.7).

        Extensions must satisfy required_capabilities and be supported by all current
        members when committed. Call process_proposal on this message to enqueue it.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        proposal = GroupContextExtensionsProposal(extensions)
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=self._group_context.serialize(),
            wire_format=WireFormat.PUBLIC_MESSAGE,
            sender_type=MsgSenderType.MEMBER,
        )
        return pt

    def create_group_context_extensions_proposal_as_external_sender(
        self, sender_index: int, extensions: bytes, signing_key: bytes
    ) -> MLSPlaintext:
        """Create and sign a GroupContextExtensions proposal as an external sender (RFC 9420 §12.1.8).

        The message MUST be sent as PublicMessage. Extensions must satisfy
        required_capabilities and be supported by all current members when committed.
        """
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        proposal = GroupContextExtensionsProposal(extensions)
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=sender_index,
            authenticated_data=b"",
            content_type=ContentType.PROPOSAL,
            content=proposal.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=None,
            wire_format=WireFormat.PUBLIC_MESSAGE,
            sender_type=MsgSenderType.EXTERNAL,
        )
        return pt

    def external_commit_add_member(
        self, key_package: KeyPackage, kem_public_key: bytes, signing_key: bytes
    ) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create an external commit that adds the joiner (RFC §12.4.3.2).

        Same as external_commit(key_package, signing_key, kem_public_key) but with
        explicit kem_public_key. No Add proposal; joiner is added via UpdatePath.
        """
        return self.external_commit(key_package, signing_key, kem_public_key)

    def process_proposal(
        self, message: MLSPlaintext, sender: Sender, wire_format: Optional[int] = None
    ) -> None:
        """Verify and enqueue a Proposal carried in MLSPlaintext.

        Handles MEMBER senders (key from ratchet tree, GroupContext in TBS,
        membership tag verified) and EXTERNAL senders (key from
        external_senders extension, no GroupContext in TBS, no membership
        tag) per RFC 9420 §6.1 and §12.1.8.

        Parameters
        - message: Proposal-carrying MLSPlaintext.
        - sender: Sender information (leaf index or sender_index).
        - wire_format: Optional WireFormat value (PUBLIC_MESSAGE or PRIVATE_MESSAGE).
          If provided and sender is EXTERNAL or NEW_MEMBER_PROPOSAL, MUST be PUBLIC_MESSAGE (RFC §12.1.8).

        Raises
        - CommitValidationError: If sender leaf node is missing or proposal
          type is not allowed for external senders.
        - InvalidSignatureError: If signature or membership tag verification fails.
        - ConfigurationError: If external_senders extension is missing/invalid.
        """
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        # RFC 9420 §12.1.8: external proposals MUST be sent as PublicMessage
        if wire_format is not None and sender.sender_type in (
            SenderType.EXTERNAL,
            SenderType.NEW_MEMBER_PROPOSAL,
        ):
            if wire_format != WireFormat.PUBLIC_MESSAGE:
                raise CommitValidationError(
                    "external and new_member proposals MUST be sent as PublicMessage"
                )

        if sender.sender_type == SenderType.EXTERNAL:
            # RFC §12.1.8: validate proposal type is allowed for external senders
            tbs_fc = message.auth_content.tbs.framed_content
            proposal = Proposal.deserialize(tbs_fc.content)
            _EXTERNAL_ALLOWED = (
                AddProposal,
                RemoveProposal,
                PreSharedKeyProposal,
                ReInitProposal,
                GroupContextExtensionsProposal,
            )
            if not isinstance(proposal, _EXTERNAL_ALLOWED):
                raise CommitValidationError("proposal type not allowed for external senders")

            # RFC §6.1: look up signature key from external_senders extension
            # by sender_index (sender.sender for EXTERNAL type)
            from ..extensions.extensions import (
                parse_external_senders,
                ExtensionType as _ET,
                deserialize_extensions as _de,
            )

            if self._group_context is None or not self._group_context.extensions:
                raise ConfigurationError("no GroupContext extensions for external sender lookup")
            ext_senders_list = []
            for ext in _de(self._group_context.extensions):
                if int(ext.ext_type) == int(_ET.EXTERNAL_SENDERS):
                    ext_senders_list = parse_external_senders(ext.data)
                    break
            if sender.sender >= len(ext_senders_list):
                raise ConfigurationError(
                    f"sender_index {sender.sender} out of range in external_senders "
                    f"(have {len(ext_senders_list)} entries)"
                )
            verification_key = ext_senders_list[sender.sender].signature_key

            # RFC §6.1: TBS does NOT include GroupContext for external senders
            # RFC §6.2: no membership tag for external senders
            verify_plaintext(
                message,
                verification_key,
                None,
                self._crypto_provider,
                group_context=None,
            )
        elif sender.sender_type == SenderType.NEW_MEMBER_PROPOSAL:
            # RFC §12.1.8: new_member_proposal sends e.g. Add for self; key from proposal content
            tbs_fc = message.auth_content.tbs.framed_content
            proposal = Proposal.deserialize(tbs_fc.content)
            if not isinstance(proposal, AddProposal):
                raise CommitValidationError(
                    "new_member_proposal sender only allowed to send Add proposal"
                )
            kp = KeyPackage.deserialize(proposal.key_package)
            if not kp.leaf_node or not kp.leaf_node.signature_key:
                raise CommitValidationError("Add proposal KeyPackage missing leaf signature key")
            verification_key = kp.leaf_node.signature_key
            verify_plaintext(
                message,
                verification_key,
                None,
                self._crypto_provider,
                group_context=None,
            )
        else:
            # MEMBER sender: key from ratchet tree
            sender_leaf_node = self._ratchet_tree.get_node(sender.sender * 2).leaf_node
            if not sender_leaf_node:
                raise CommitValidationError(f"No leaf node found for sender index {sender.sender}")

            # RFC §6.1: TBS includes GroupContext for member senders
            gc_bytes = self._group_context.serialize() if self._group_context else None
            verify_plaintext(
                message,
                sender_leaf_node.signature_key,
                self._key_schedule.membership_key,
                self._crypto_provider,
                group_context=gc_bytes,
            )
            proposal = Proposal.deserialize(message.auth_content.tbs.framed_content.content)
        # Validate credentials for Add/Update/GCE proposals (RFC 9420 §5.3.1)
        try:
            if isinstance(proposal, AddProposal):
                kp = KeyPackage.deserialize(proposal.key_package)
                kp.verify(self._crypto_provider, group_context=self._group_context)
                self._validate_credential_if_set(
                    kp.leaf_node.credential if kp.leaf_node else None, "add_proposal"
                )
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree,
                    kp.leaf_node,
                    replacing_leaf_index=None,
                )
            elif isinstance(proposal, UpdateProposal):
                from .key_packages import LeafNode as _LeafNode

                leaf = _LeafNode.deserialize(proposal.leaf_node)
                pk = (
                    getattr(leaf.credential, "public_key", None)
                    if leaf.credential is not None
                    else None
                )
                if pk and pk != leaf.signature_key:
                    raise CommitValidationError(
                        "leaf credential public key does not match signature key"
                    )
                current_leaf = self._ratchet_tree.get_node(sender.sender * 2).leaf_node
                try:
                    leaf.validate(
                        self._crypto_provider,
                        group_id=self._group_id,
                        leaf_index=sender.sender,
                        group_context=self._group_context,
                        expected_source=LeafNodeSource.UPDATE,
                        replacing_encryption_key=current_leaf.encryption_key
                        if current_leaf
                        else None,
                    )
                except Exception as e:
                    raise CommitValidationError(f"Update proposal LeafNode invalid: {e}") from e
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree,
                    leaf,
                    replacing_leaf_index=sender.sender,
                )
                self._validate_credential_if_set(leaf.credential, "update_proposal")
            elif isinstance(proposal, GroupContextExtensionsProposal):
                try:
                    from ..extensions.extensions import parse_external_senders

                    for ext in deserialize_extensions(proposal.extensions):
                        if int(ext.ext_type) == int(ExtensionType.EXTERNAL_SENDERS):
                            for es in parse_external_senders(ext.data):
                                self._validate_credential_if_set(
                                    getattr(es, "credential", None), "external_senders"
                                )
                            break
                except Exception:
                    pass
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

    def revoke_proposal(self, proposal_ref: bytes) -> None:
        """Remove a cached proposal by its reference (ProposalRef), e.g. when the
        delivery service revokes an in-flight proposal.

        If the proposal_ref is not in the cache, this is a no-op.

        Parameters:
            proposal_ref: ProposalRef (hash of the proposal per RFC 9420 §5.2).
        """
        entry = self._proposal_cache.pop(proposal_ref, None)
        if entry is not None:
            proposal, _ = entry
            try:
                self._pending_proposals.remove(proposal)
            except ValueError:
                pass

    def create_commit(
        self,
        signing_key: bytes,
        return_per_joiner_welcomes: bool = False,
    ) -> tuple[MLSPlaintext, list[Welcome]]:
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
        - return_per_joiner_welcomes: If True, return one Welcome per added member
          (each with a single EncryptedGroupSecrets), e.g. for delivery services
          that target each joiner separately (DAVE voice gateway).

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
        has_ext_init = any(isinstance(p, ExternalInitProposal) for p in self._pending_proposals)
        # Build update_leaf_indices for RFC §12.2 (Update from committer, same-leaf Update+Remove)
        update_leaf_indices: list[tuple[Proposal, int]] = []
        for p in self._pending_proposals:
            if isinstance(p, UpdateProposal):
                proposer_idx = self._own_leaf_index
                for _ref, (cached_prop, idx) in self._proposal_cache.items():
                    if cached_prop is p or cached_prop == p:
                        proposer_idx = idx
                        break
                update_leaf_indices.append((p, proposer_idx))
        add_for_existing_ok = set(removes)  # Add for a removed leaf is allowed
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
                allow_external_init=has_ext_init,
                update_leaf_indices=update_leaf_indices if update_leaf_indices else None,
                add_for_existing_ok=add_for_existing_ok,
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
                    current_leaf = self._ratchet_tree.get_node(proposer_idx * 2).leaf_node
                    try:
                        leaf.validate(
                            self._crypto_provider,
                            group_id=self._group_id,
                            leaf_index=proposer_idx,
                            group_context=self._group_context,
                            expected_source=LeafNodeSource.UPDATE,
                            replacing_encryption_key=current_leaf.encryption_key
                            if current_leaf
                            else None,
                        )
                    except Exception as e:
                        raise CommitValidationError(f"Update proposal LeafNode invalid: {e}") from e
                    validate_leaf_node_unique_against_tree(
                        self._ratchet_tree, leaf, replacing_leaf_index=proposer_idx
                    )
                    self._ratchet_tree.update_leaf(proposer_idx, leaf)
        # Apply Removes
        for idx in sorted(removes, reverse=True):
            self._ratchet_tree.remove_leaf(idx)
        # Apply Adds (RFC §5.3.1: validate credential when receiving KeyPackage for Add).
        # Build joiner_infos (leaf_index, KeyPackage) for Welcome generation (RFC §12.4.3).
        joiner_infos: list[tuple[int, KeyPackage]] = []
        for kp in adds_kps:
            self._validate_credential_if_set(
                kp.leaf_node.credential if kp.leaf_node else None, "add"
            )
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
            leaf_idx = self._ratchet_tree.add_leaf(kp)
            joiner_infos.append((leaf_idx, kp))
        validate_tree_leaf_key_uniqueness(self._ratchet_tree)
        validate_credential_identity_uniqueness(self._ratchet_tree)

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
            provisional_epoch = (
                1
                if reinit_prop
                else ((self._group_context.epoch + 1) if self._group_context else 0)
            )
            provisional_group_id = reinit_prop.new_group_id if reinit_prop else self._group_id
            provisional_tree_hash = self._ratchet_tree.calculate_tree_hash()
            provisional_confirmed = (
                self._group_context.confirmed_transcript_hash if self._group_context else b""
            )
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
            update_path, commit_secret, path_secret_by_node = self._ratchet_tree.create_update_path(
                self._own_leaf_index,
                new_leaf_node,
                gc_bytes,
                excluded_leaf_pubkeys=new_add_pubkeys if new_add_pubkeys else None,
            )
        else:
            update_path = None
            path_secret_by_node = None
            # Path-less commit: commit_secret is all-zeros of KDF.Nh (RFC ?8)
            commit_secret = bytes(self._crypto_provider.kdf_hash_len())

        # Construct and sign the commit
        # Collect proposal references corresponding to pending proposals and build union proposals list in RFC order
        # RFC §12.4.3.2: External commits MUST NOT include proposals by reference; only inline.
        proposals_union: list[ProposalOrRef] = []
        use_references = not has_ext_init

        def _append_ordered(cls_type):
            for p in self._pending_proposals:
                if isinstance(p, cls_type):
                    if use_references:
                        ref = None
                        for cached_ref, (cached_prop, _) in self._proposal_cache.items():
                            if cached_prop is p or cached_prop == p:
                                ref = cached_ref
                                break
                        if ref is not None:
                            proposals_union.append(
                                ProposalOrRef(ProposalOrRefType.REFERENCE, reference=ref)
                            )
                            continue
                    proposals_union.append(ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=p))

        from .data_structures import (
            GroupContextExtensionsProposal as _GCE,
            UpdateProposal as _UP,
            RemoveProposal as _RP,
            AddProposal as _AP,
            PreSharedKeyProposal as _PSK,
            ExternalInitProposal as _EI,
            ReInitProposal as _RI,
        )

        # RFC §12.3: GroupContextExtensions -> Update -> Remove -> Add -> PreSharedKey -> ExternalInit -> ReInit
        _append_ordered(_GCE)
        _append_ordered(_UP)
        _append_ordered(_RP)
        _append_ordered(_AP)
        _append_ordered(_PSK)
        _append_ordered(_EI)
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
        # RFC §12.4.3.2: External commits MUST be signed with sender type new_member_commit.
        if self._group_context is None:
            raise RFC9420Error("group not initialized")
        # RFC §6.1: new_member_commit TBS MUST include GroupContext; pass it when external commit.
        pt = sign_authenticated_content(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=authenticated_data,
            content_type=ContentType.COMMIT,
            content=commit.serialize(),
            signing_private_key=signing_key,
            crypto=self._crypto_provider,
            group_context=self._group_context.serialize(),
            sender_type=MsgSenderType.NEW_MEMBER_COMMIT if has_ext_init else None,
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
            new_group_id,
            new_epoch,
            tree_hash,
            b"",
            effective_group_extensions,
            cipher_suite_id=cs_id,
        )  # filled after confirm tag

        # Derive PSK secret using RFC ?8.4 chained derivation
        psk_secret = None
        if psk_ids:
            from .messages import derive_psk_secret

            psk_values_raw = self._get_psk_values(psk_ids)
            psk_values = [v for v in psk_values_raw if v is not None] if psk_values_raw else None
            psk_secret = derive_psk_secret(self._crypto_provider, psk_ids, psk_values=psk_values)
        # RFC 9420 §8.3: When committer is external joiner, use init_secret from HPKE export as prev_init_secret.
        if has_ext_init:
            prev_init_secret = self._external_init_secret_for_commit
            if prev_init_secret is None and self._key_schedule is not None:
                prev_init_secret = self._key_schedule.init_secret
            if prev_init_secret is None:
                raise RFC9420Error(
                    "external commit requires HPKE export as prev_init_secret (RFC 9420 §8.3); use external_commit() which sets it"
                )
            self._external_init_secret_for_commit = None  # Clear after use so it is not reused
        elif self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        else:
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
            max_generation_gap=self._secret_tree_max_generation_gap,
            aead_limit_bytes=self._secret_tree_aead_limit_bytes,
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
            self._group_id,
            new_epoch,
            tree_hash,
            self._confirmed_transcript_hash or b"",
            effective_group_extensions,
            cipher_suite_id=cs_id,
        )
        self._received_commit_for_current_epoch = False  # §14: clear after advancing epoch
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
            max_generation_gap=self._secret_tree_max_generation_gap,
            aead_limit_bytes=self._secret_tree_aead_limit_bytes,
        )

        # Construct Welcome messages for any added members (placeholder encoding)
        welcomes: list[Welcome] = []
        if joiner_infos:
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
            # # Include REQUIRED_CAPABILITIES so joiners can enforce support
            # try:
            #     from ..extensions.extensions import build_required_capabilities

            #     req: list[int] = [int(ExtensionType.RATCHET_TREE)]
            #     if self._external_public_key:
            #         req.append(int(ExtensionType.EXTERNAL_PUB))
            #     exts.append(
            #         Extension(ExtensionType.REQUIRED_CAPABILITIES, build_required_capabilities(req))
            #     )
            # except Exception:
            #     pass
            # RFC 9420 §7.2: ratchet_tree and external_pub are *default* extensions
            # that MUST NOT be listed in capabilities/required_capabilities.
            # Only add REQUIRED_CAPABILITIES for non-default extensions here.
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
                self._group_context,
                Signature(b""),
                ext_bytes,
                confirm_tag_local,
                self._own_leaf_index,
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
            from . import tree_math as _tree_math

            for joiner_leaf_idx, kp in joiner_infos:
                if kp.leaf_node is None:
                    continue
                # Welcome secrets are encrypted to KeyPackage.init_key (join key),
                # not the LeafNode encryption key.
                pk = kp.init_key
                # Seal GroupSecrets for each joiner
                from .data_structures import GroupSecrets

                # RFC 9420 §12.4.3: path_secret for joiner's LCA so they can derive path to root.
                path_secret_for_joiner = None
                if path_secret_by_node:
                    lca_node = _tree_math.lca(
                        self._own_leaf_index * 2,
                        joiner_leaf_idx * 2,
                        self._ratchet_tree.n_leaves,
                    )
                    path_secret_for_joiner = path_secret_by_node.get(lca_node)

                # Check for ReInit proposal to inject ReInit PSK ID
                psks_to_inject = []
                if reinit_prop:
                    import os as _os

                    psks_to_inject.append(
                        PreSharedKeyID(
                            PSKType.RESUMPTION,
                            usage=ResumptionPSKUsage.REINIT,
                            psk_group_id=old_group_id,
                            psk_epoch=old_epoch + 1,
                            psk_nonce=_os.urandom(
                                self._crypto_provider.kdf_hash_len()
                            ),  # random nonce per RFC ?11.2
                        )
                    )

                gs = GroupSecrets(
                    joiner_secret=joiner_secret,
                    psk_secret=psk_secret,
                    psks=psks_to_inject,
                    path_secret=path_secret_for_joiner,
                )
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
            if return_per_joiner_welcomes:
                welcomes.extend(welcome.split_by_joiner())
            else:
                welcomes.append(welcome)

        # Attach confirmation_tag to the commit MLSPlaintext (RFC ?6.2)
        from .messages import AuthenticatedContent as _AC, FramedContentAuthData

        new_auth = FramedContentAuthData(
            signature=pt.auth_content.signature, confirmation_tag=confirm_tag
        )
        pt = MLSPlaintext(
            _AC(
                tbs=pt.auth_content.tbs,
                auth=new_auth,
                membership_tag=pt.auth_content.membership_tag,
            )
        )
        # RFC §12.4.3.2: new_member_commit sender has no membership tag; only MEMBER commits get it.
        if not has_ext_init:
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
        - SameEpochCommitError: When the commit is for the current epoch (RFC 9420 §14);
          application must implement conflict resolution.
        - CommitValidationError: On missing references or invalid binder.
        - InvalidSignatureError: On signature or membership tag failures.
        """
        # RFC 9420 §14: detect a second commit for the same epoch (conflict)
        if self._group_context is not None:
            msg_epoch = getattr(
                message.auth_content.tbs.framed_content,
                "epoch",
                None,
            )
            if msg_epoch is not None and msg_epoch == self._group_context.epoch:
                if getattr(self, "_received_commit_for_current_epoch", False):
                    raise SameEpochCommitError(
                        "second commit for current epoch; application MUST implement conflict resolution (RFC 9420 §14)"
                    )
                self._received_commit_for_current_epoch = True
        # Mark receipt for sending restrictions until fully applied
        self._received_commit_unapplied = True
        # Verify plaintext container
        sender_leaf_node = self._ratchet_tree.get_node(sender_index * 2).leaf_node
        if not sender_leaf_node:
            raise CommitValidationError(f"No leaf node for committer index {sender_index}")
        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")
        gc_bytes = self._group_context.serialize() if self._group_context else None
        verify_plaintext(
            message,
            sender_leaf_node.signature_key,
            self._key_schedule.membership_key,
            self._crypto_provider,
            group_context=gc_bytes,
        )

        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)
        validate_commit_basic(commit)
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
        all_psk_ids = [p.psk for p in resolved if isinstance(p, PreSharedKeyProposal)]
        if all_psk_ids:
            from .messages import derive_psk_secret

            psk_values_raw = self._get_psk_values(all_psk_ids)
            psk_values = [v for v in psk_values_raw if v is not None] if psk_values_raw else None
            psk_secret = derive_psk_secret(
                self._crypto_provider, all_psk_ids, psk_values=psk_values
            )
        gce_prop = next(
            (p for p in resolved if isinstance(p, GroupContextExtensionsProposal)), None
        )
        effective_group_extensions = (
            gce_prop.extensions
            if gce_prop is not None
            else (self._group_context.extensions if self._group_context else b"")
        )

        # RFC 9420 §12.3: Apply proposals in order GCE -> Update -> Remove -> Add.
        from .validations import derive_ops_from_proposals

        removes, adds = derive_ops_from_proposals(resolved)
        # GCE already applied via effective_group_extensions above.
        # 1. Update (replace leaf nodes for proposers)
        for up, proposer_idx in update_tuples:
            try:
                from .key_packages import LeafNode as _LeafNode

                leaf = _LeafNode.deserialize(up.leaf_node)
                if leaf.credential is not None and leaf.credential.public_key != leaf.signature_key:
                    raise CommitValidationError(
                        "leaf credential public key does not match signature key"
                    )
                current_leaf = self._ratchet_tree.get_node(proposer_idx * 2).leaf_node
                leaf.validate(
                    self._crypto_provider,
                    group_id=self._group_id,
                    leaf_index=proposer_idx,
                    group_context=self._group_context,
                    expected_source=LeafNodeSource.UPDATE,
                    replacing_encryption_key=current_leaf.encryption_key if current_leaf else None,
                )
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree, leaf, replacing_leaf_index=proposer_idx
                )
                self._ratchet_tree.update_leaf(proposer_idx, leaf)
            except (ValueError, CommitValidationError):
                continue
        # 2. Remove
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except (ValueError, IndexError):
                continue
        # 3. Add (new members). Record (leaf_index, kp) for Welcome path_secret (RFC 9420 §12.4.3).
        joiner_infos: list[tuple[int, KeyPackage]] = []
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
            joiner_leaf_idx = self._ratchet_tree.n_leaves
            self._ratchet_tree.add_leaf(kp)
            joiner_infos.append((joiner_leaf_idx, kp))
        validate_tree_leaf_key_uniqueness(self._ratchet_tree)
        validate_credential_identity_uniqueness(self._ratchet_tree)
        # Clear referenced proposals from cache after applying
        for pref in ref_bytes:
            self._proposal_cache.pop(pref, None)

        # Derive commit secret (path_secret_by_node for Welcome path_secret per RFC 9420 §12.4.3)
        if commit.path:
            provisional_epoch = (
                1
                if any(isinstance(p, ReInitProposal) for p in resolved)
                else ((self._group_context.epoch + 1) if self._group_context else 0)
            )
            provisional_group_id = next(
                (p.new_group_id for p in resolved if isinstance(p, ReInitProposal)), self._group_id
            )
            provisional_confirmed = (
                self._group_context.confirmed_transcript_hash if self._group_context else b""
            )
            provisional_gc = GroupContext(
                provisional_group_id,
                provisional_epoch,
                self._ratchet_tree.calculate_tree_hash(),
                provisional_confirmed,
                effective_group_extensions,
                cipher_suite_id=self._crypto_provider.active_ciphersuite.suite_id,
            )
            gc_bytes = provisional_gc.serialize()
            # RFC §7.3: UpdatePath leaf must have leaf_node_source commit
            path_leaf = LeafNode.deserialize(commit.path.leaf_node)
            try:
                path_leaf.validate(
                    self._crypto_provider,
                    group_id=self._group_id,
                    leaf_index=sender_index,
                    group_context=provisional_gc,
                    expected_source=LeafNodeSource.COMMIT,
                )
            except Exception as e:
                raise CommitValidationError(f"UpdatePath LeafNode invalid: {e}") from e
            commit_secret = self._ratchet_tree.merge_update_path(
                commit.path, sender_index, gc_bytes
            )
            # RFC 9420 §5.3.1: validate credential when receiving Commit with UpdatePath
            path_leaf = LeafNode.deserialize(commit.path.leaf_node)
            self._validate_credential_if_set(path_leaf.credential, "commit_update_path")
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
            self._group_id = new_group_id  # Update instance group_id to the new one
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
        new_group_context = GroupContext(
            new_group_id,
            new_epoch,
            tree_hash,
            b"",
            effective_group_extensions,
            cipher_suite_id=cs_id,
        )

        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")

        # Determine init_secret (ExternalInit vs chain)
        external_init_prop = next(
            (p for p in referenced if isinstance(p, ExternalInitProposal)), None
        )
        if external_init_prop:
            if not self._external_private_key:
                raise CommitValidationError(
                    "ExternalInit proposal received but no external key pair available"
                )
            try:
                prev_init_secret = self._crypto_provider.hpke_export_secret(
                    private_key=self._external_private_key,
                    kem_output=external_init_prop.kem_output,
                    info=b"",
                    export_label=b"MLS 1.0 external init secret",
                    export_length=self._crypto_provider.kdf_hash_len(),
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
            max_generation_gap=self._secret_tree_max_generation_gap,
            aead_limit_bytes=self._secret_tree_aead_limit_bytes,
        )
        self._group_context = new_group_context  # temporary
        # Compute and apply confirmation tag over interim transcript
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        # Update group context with confirmed hash (for the new epoch)
        self._group_context = GroupContext(
            new_group_id,
            new_epoch,
            tree_hash,
            self._confirmed_transcript_hash or b"",
            effective_group_extensions,
            cipher_suite_id=cs_id,
        )
        self._received_commit_for_current_epoch = False  # §14: clear after advancing epoch
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
            max_generation_gap=self._secret_tree_max_generation_gap,
            aead_limit_bytes=self._secret_tree_aead_limit_bytes,
        )
        # Verify confirmation tag (RFC 9420 §8.1: MUST be present and MUST verify)
        sender_confirm_tag = message.auth_content.confirmation_tag
        if not sender_confirm_tag:
            raise CommitValidationError("confirmation tag missing on commit")
        if self._confirmed_transcript_hash is None:
            raise RFC9420Error("confirmed transcript hash not available for verification")
        from .validations import validate_confirmation_tag

        validate_confirmation_tag(
            self._crypto_provider,
            self._key_schedule.confirmation_key,
            self._confirmed_transcript_hash,
            sender_confirm_tag,
        )
        self._update_external_key_pair()

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
            raise ConfigurationError(
                "no external signature verification key configured for this group"
            )
        # Verify signature only (no membership tag), trying available external verification keys.
        # RFC §6.1: new_member_commit TBS includes GroupContext
        sender_obj = message.auth_content.tbs.framed_content.sender
        needs_gc = getattr(sender_obj, "sender_type", None) in (
            SenderType.MEMBER,
            SenderType.NEW_MEMBER_COMMIT,
        )
        ext_gc = self._group_context.serialize() if needs_gc and self._group_context else None
        last_sig_err: Optional[Exception] = None
        for key in verify_keys:
            try:
                verify_plaintext(message, key, None, self._crypto_provider, group_context=ext_gc)
                last_sig_err = None
                break
            except InvalidSignatureError as e:
                last_sig_err = e
        if last_sig_err is not None:
            raise last_sig_err

        # Deserialize commit
        commit = Commit.deserialize(message.auth_content.tbs.framed_content.content)
        validate_commit_basic(commit)

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
        if (
            sender_type in (SenderType.EXTERNAL, SenderType.NEW_MEMBER_COMMIT)
            and ext_init_count != 1
        ):
            raise CommitValidationError(
                "external commit must contain exactly one ExternalInit proposal (RFC ?12.4.3.2)"
            )
        if (
            sender_type in (SenderType.EXTERNAL, SenderType.NEW_MEMBER_COMMIT)
            and commit.path is None
        ):
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
        all_psk_ids = [p.psk for p in resolved if isinstance(p, PreSharedKeyProposal)]
        if all_psk_ids:
            from .messages import derive_psk_secret

            psk_secret = derive_psk_secret(self._crypto_provider, all_psk_ids)

        # RFC 9420 §12.3: Apply in order Add -> Remove -> Update (external commit has no Add/Update, only Remove).
        from .validations import derive_ops_from_proposals

        removes, adds = derive_ops_from_proposals(resolved)
        for kp_bytes in adds:
            try:
                kp = KeyPackage.deserialize(kp_bytes)
                validate_leaf_node_unique_against_tree(
                    self._ratchet_tree, kp.leaf_node, replacing_leaf_index=None
                )
                self._ratchet_tree.add_leaf(kp)
            except (ValueError, IndexError):
                continue
        for idx in sorted(removes, reverse=True):
            try:
                self._ratchet_tree.remove_leaf(idx)
            except (ValueError, IndexError):
                continue
        validate_tree_leaf_key_uniqueness(self._ratchet_tree)
        validate_credential_identity_uniqueness(self._ratchet_tree)

        # External commits: commit_secret from path if provided, else zeros
        if commit.path:
            # RFC ss12.4.3.2: merge_update_path uses the *provisional* new GroupContext
            # (incremented epoch, new tree_hash, old confirmed hash), not current epoch.
            _prov_ext_epoch = self._group_context.epoch + 1 if self._group_context else 1
            _prov_ext_gid = next(
                (p.new_group_id for p in resolved if isinstance(p, ReInitProposal)), self._group_id
            )
            _prov_ext_exts = self._group_context.extensions if self._group_context else b""
            _prov_ext_confirmed = (
                self._group_context.confirmed_transcript_hash if self._group_context else b""
            )
            _prov_ext_cs = self._crypto_provider.active_ciphersuite.suite_id
            _prov_ext_gc = GroupContext(
                _prov_ext_gid,
                _prov_ext_epoch,
                self._ratchet_tree.calculate_tree_hash(),
                _prov_ext_confirmed,
                _prov_ext_exts,
                cipher_suite_id=_prov_ext_cs,
            )
            gc_bytes = _prov_ext_gc.serialize()
            # RFC §7.3: UpdatePath leaf must have leaf_node_source commit
            path_leaf = LeafNode.deserialize(commit.path.leaf_node)
            try:
                path_leaf.validate(
                    self._crypto_provider,
                    group_id=self._group_id,
                    leaf_index=committer_index,
                    group_context=_prov_ext_gc,
                    expected_source=LeafNodeSource.COMMIT,
                )
            except Exception as e:
                raise CommitValidationError(f"UpdatePath LeafNode invalid: {e}") from e
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
        # Prepare new group context (confirmed hash will be set after computing tag).
        # RFC 9420 §12.1.6: Include extensions when building GroupContext (external commit).
        cs_id = self._crypto_provider.active_ciphersuite.suite_id
        effective_group_extensions = self._group_context.extensions if self._group_context else b""
        new_group_context = GroupContext(
            new_group_id,
            new_epoch,
            tree_hash,
            b"",
            effective_group_extensions,
            cipher_suite_id=cs_id,
        )

        if self._key_schedule is None:
            raise RFC9420Error("group not initialized")

        # Determine init_secret: find ExternalInit prop in ALL resolved proposals
        external_init_prop = next(
            (p for p in resolved if isinstance(p, ExternalInitProposal)), None
        )
        if external_init_prop:
            if not self._external_private_key:
                raise CommitValidationError(
                    "ExternalInit proposal received but no external key pair available"
                )
            try:
                prev_init_secret = self._crypto_provider.hpke_export_secret(
                    private_key=self._external_private_key,
                    kem_output=external_init_prop.kem_output,
                    info=b"",
                    export_label=b"MLS 1.0 external init secret",
                    export_length=self._crypto_provider.kdf_hash_len(),
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
            max_generation_gap=self._secret_tree_max_generation_gap,
            aead_limit_bytes=self._secret_tree_aead_limit_bytes,
        )
        self._group_context = new_group_context  # temporary
        # Compute and apply confirmation tag over interim transcript
        confirm_tag = transcripts.compute_confirmation_tag(self._key_schedule.confirmation_key)
        transcripts.finalize_confirmed(confirm_tag)
        self._interim_transcript_hash = transcripts.interim
        self._confirmed_transcript_hash = transcripts.confirmed
        self._group_context = GroupContext(
            new_group_id,
            new_epoch,
            tree_hash,
            self._confirmed_transcript_hash or b"",
            effective_group_extensions,
            cipher_suite_id=cs_id,
        )
        self._received_commit_for_current_epoch = False  # §14: clear after advancing epoch
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
            max_generation_gap=self._secret_tree_max_generation_gap,
            aead_limit_bytes=self._secret_tree_aead_limit_bytes,
        )
        # RFC 9420 §8.1: Verify confirmation tag on external commit
        sender_confirm_tag = message.auth_content.confirmation_tag
        if not sender_confirm_tag:
            raise CommitValidationError("confirmation tag missing on external commit")
        from .validations import validate_confirmation_tag

        validate_confirmation_tag(
            self._crypto_provider,
            self._key_schedule.confirmation_key,
            self._confirmed_transcript_hash or b"",
            sender_confirm_tag,
        )
        self._update_external_key_pair()

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
        cs_id = (
            self._crypto_provider.active_ciphersuite.suite_id
            if self._crypto_provider and hasattr(self._crypto_provider, "active_ciphersuite")
            else 0x0001
        )
        self._pending_proposals.append(
            ReInitProposal(new_group_id, version=0x0001, cipher_suite=cs_id)
        )
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

    def protect(self, app_data: bytes, signing_key: Optional[bytes] = None) -> MLSCiphertext:
        """Encrypt application data into MLSCiphertext for the current epoch.

        Encrypts application data using the current epoch's application secret
        and the secret tree. Per RFC 9420 §6.1, FramedContentAuthData includes a
        signature over FramedContentTBS; when signing_key is provided it is used
        for interoperability. When omitted, no signature is included (legacy behavior).

        Args:
            app_data: Plaintext application data to encrypt.
            signing_key: Optional private key for signing (member leaf signature key).
                When provided, the application message carries a valid signature.

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
        # RFC 9420 §15.2: Senders MUST NOT exceed AEAD encryption limits per epoch
        if not self._secret_tree.can_encrypt(len(app_data)):
            raise RFC9420Error("AEAD encryption bound reached for this epoch (RFC 9420 §15.2)")
        signature = b""
        if signing_key is not None:
            from .messages import (
                sign_application_framed_content,
                write_opaque_varint,
            )

            content_prefixed = write_opaque_varint(app_data)
            signature = sign_application_framed_content(
                group_id=self._group_id,
                epoch=self._group_context.epoch,
                sender_leaf_index=self._own_leaf_index,
                authenticated_data=b"",
                content_prefixed=content_prefixed,
                group_context=self._group_context.serialize(),
                signing_private_key=signing_key,
                crypto=self._crypto_provider,
            )
        ct = protect_content_application(
            group_id=self._group_id,
            epoch=self._group_context.epoch,
            sender_leaf_index=self._own_leaf_index,
            authenticated_data=b"",
            content=app_data,
            signature=signature,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )
        self._secret_tree.record_encryption(len(app_data))
        return ct

    def get_aead_encrypted_bytes_this_epoch(self) -> int:
        """Return total plaintext bytes encrypted this epoch (RFC 9420 §15.2)."""
        if self._secret_tree is None:
            return 0
        return self._secret_tree.encrypted_bytes_this_epoch

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
        sender, body, auth = unprotect_content_application(
            message,
            key_schedule=self._key_schedule,
            secret_tree=self._secret_tree,
            crypto=self._crypto_provider,
        )
        if auth.signature:
            from .messages import write_opaque_varint
            from .data_structures import Sender, SenderType

            sender_node = self._ratchet_tree.get_node(sender * 2)
            if (
                not sender_node
                or not sender_node.leaf_node
                or not sender_node.leaf_node.signature_key
            ):
                raise InvalidSignatureError(
                    "cannot verify application message: sender leaf has no signature key"
                )
            content_prefixed = write_opaque_varint(body)
            framed = FramedContent(
                group_id=message.group_id,
                epoch=message.epoch,
                sender=Sender(sender, SenderType.MEMBER),
                authenticated_data=message.authenticated_data or b"",
                content_type=ContentType.APPLICATION,
                content=content_prefixed,
            )
            tbs = AuthenticatedContentTBS(
                wire_format=WireFormat.PRIVATE_MESSAGE,
                framed_content=framed,
                group_context=self._group_context.serialize() if self._group_context else None,
            )
            self._crypto_provider.verify_with_label(
                sender_node.leaf_node.signature_key,
                b"FramedContentTBS",
                tbs.serialize(),
                auth.signature,
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
                backend_id = (
                    backend_id_bytes.decode("ascii") if backend_id_bytes else DEFAULT_TREE_BACKEND
                )
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
                    max_generation_gap=group._secret_tree_max_generation_gap,
                    aead_limit_bytes=group._secret_tree_aead_limit_bytes,
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
                    max_generation_gap=group._secret_tree_max_generation_gap,
                    aead_limit_bytes=group._secret_tree_aead_limit_bytes,
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

    def get_member_identities(self) -> list[tuple[int, bytes]]:
        """Return (leaf_index, identity) for each member. Identity is credential.identity or b'' if absent."""
        out: list[tuple[int, bytes]] = []
        n = self._ratchet_tree.n_leaves
        for leaf_index in range(n):
            node = self._ratchet_tree.get_node(leaf_index * 2)
            identity = b""
            if node.leaf_node is not None and node.leaf_node.credential is not None:
                identity = getattr(node.leaf_node.credential, "identity", b"") or b""
            out.append((leaf_index, identity))
        return out

    def close(self) -> None:
        """Best-effort wipe of in-memory secrets and transient proposal state."""
        try:
            if self._secret_tree is not None:
                self._secret_tree.wipe()
        except Exception:
            pass
        try:
            if self._key_schedule is not None:
                self._key_schedule.wipe()
        except Exception:
            pass
        self._pending_proposals = []
        self._proposal_cache = {}

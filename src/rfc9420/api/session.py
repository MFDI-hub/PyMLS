from __future__ import annotations

from typing import Tuple, List, TYPE_CHECKING

from ..mls.group import Group
from ..protocol.key_packages import KeyPackage, LeafNode
from ..protocol.data_structures import Welcome
from ..crypto.crypto_provider import CryptoProvider
from ..protocol.ratchet_tree_backend import DEFAULT_TREE_BACKEND
from ..interop.wire import (
    encode_handshake,
    decode_handshake,
    encode_application,
    decode_application,
)
from ..protocol.messages import MLSPlaintext, MLSCiphertext

if TYPE_CHECKING:
    from .policy import MLSAppPolicy

class MLSGroupSession:
    """Synchronous high-level session wrapper around `rfc9420.mls.Group`.

    Orchestrates group lifecycle (create/join, add/update/remove, commit/apply),
    provides byte-oriented handshake and application I/O, and exposes
    exporter-based key derivation. Not tied to any specific application protocol.

    Parameters:
        group: An existing Group instance (from create or join_from_welcome).
    """

    def __init__(self, group: Group):
        """Initialize the session with an existing Group."""
        self._group = group

    # --- Construction ---
    @classmethod
    def create(
        cls,
        group_id: bytes,
        key_package: KeyPackage,
        crypto: CryptoProvider,
        policy: "MLSAppPolicy | None" = None,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "MLSGroupSession":
        """Create a new MLS group and session as the founding member.

        Parameters:
            group_id: Unique group identifier.
            key_package: Key package for the creator (used as first member).
            crypto: Crypto provider for the group ciphersuite.
            tree_backend: Ratchet tree backend (e.g. DEFAULT_TREE_BACKEND).

        Returns:
            MLSGroupSession for the new group.
        """
        runtime_kwargs = {}
        if policy is not None:
            runtime_kwargs = {
                "secret_tree_window_size": int(policy.secret_tree_window_size),
                "max_generation_gap": int(policy.max_generation_gap),
                "aead_limit_bytes": policy.aead_limit_bytes,
            }
        sess = cls(
            Group.create(
                group_id,
                key_package,
                crypto,
                tree_backend=tree_backend,
                **runtime_kwargs,
            )
        )
        if policy is not None:
            sess.apply_policy(policy)
        return sess

    @classmethod
    def join_from_welcome(
        cls,
        welcome: Welcome,
        hpke_private_key: bytes,
        crypto: CryptoProvider,
        policy: "MLSAppPolicy | None" = None,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "MLSGroupSession":
        """Join an existing group using a Welcome message and HPKE private key.

        Parameters:
            welcome: Welcome message received from the group.
            hpke_private_key: HPKE private key matching the KeyPackage used in the Add.
            crypto: Crypto provider (must support the group ciphersuite).
            tree_backend: Ratchet tree backend.

        Returns:
            MLSGroupSession for the joined group.
        """
        runtime_kwargs = {}
        if policy is not None:
            runtime_kwargs = {
                "secret_tree_window_size": int(policy.secret_tree_window_size),
                "max_generation_gap": int(policy.max_generation_gap),
                "aead_limit_bytes": policy.aead_limit_bytes,
            }
        sess = cls(
            Group.join_from_welcome(
                welcome,
                hpke_private_key,
                crypto,
                tree_backend=tree_backend,
                **runtime_kwargs,
            )
        )
        if policy is not None:
            sess.apply_policy(policy)
        return sess

    # --- Handshake proposals and commits (byte I/O) ---
    def add_member(self, key_package: KeyPackage, signing_key: bytes) -> bytes:
        """Create an Add proposal for a new member.

        Parameters:
            key_package: Key package of the member to add.
            signing_key: Signing key for the proposal.

        Returns:
            Handshake bytes (MLSPlaintext) to send to the group.
        """
        pt: MLSPlaintext = self._group.add(key_package, signing_key)
        return encode_handshake(pt)

    def update_self(self, leaf_node: LeafNode, signing_key: bytes) -> bytes:
        """Create an Update proposal for this member's leaf.

        Parameters:
            leaf_node: New leaf node (e.g. new keys/capabilities).
            signing_key: Signing key for the proposal.

        Returns:
            Handshake bytes to send to the group.
        """
        pt: MLSPlaintext = self._group.update(leaf_node, signing_key)
        return encode_handshake(pt)

    def remove_member(self, removed_index: int, signing_key: bytes) -> bytes:
        """Create a Remove proposal for the member at the given leaf index.

        Parameters:
            removed_index: Leaf index of the member to remove.
            signing_key: Signing key for the proposal.

        Returns:
            Handshake bytes to send to the group.
        """
        pt: MLSPlaintext = self._group.remove(removed_index, signing_key)
        return encode_handshake(pt)

    def process_proposal(self, handshake_bytes: bytes, sender_leaf_index: int) -> None:
        """Process a received proposal and update internal state.

        Parameters:
            handshake_bytes: Encoded MLSPlaintext (proposal).
            sender_leaf_index: Leaf index of the sender.
        """
        pt = decode_handshake(handshake_bytes)
        self._group.process_proposal(pt, sender_leaf_index)

    def commit(self, signing_key: bytes) -> Tuple[bytes, List[Welcome]]:
        """Create a Commit covering all pending proposals and generate Welcomes.

        Parameters:
            signing_key: Signing key for the Commit.

        Returns:
            (commit_handshake_bytes, list of Welcome messages for new members).
        """
        pt, welcomes = self._group.commit(signing_key)
        return encode_handshake(pt), welcomes

    def apply_commit(self, handshake_bytes: bytes, sender_leaf_index: int) -> None:
        """Apply a received Commit and update group state.

        Parameters:
            handshake_bytes: Encoded MLSPlaintext (Commit).
            sender_leaf_index: Leaf index of the committer.
        """
        pt = decode_handshake(handshake_bytes)
        self._group.apply_commit(pt, sender_leaf_index)

    # --- Application data (byte I/O) ---
    def protect_application(self, plaintext: bytes) -> bytes:
        """Encrypt application data for the group.

        Parameters:
            plaintext: Application message to encrypt.

        Returns:
            Encoded MLSCiphertext bytes.
        """
        ct: MLSCiphertext = self._group.protect(plaintext)
        return encode_application(ct)

    def unprotect_application(self, ciphertext_bytes: bytes) -> Tuple[int, bytes]:
        """Decrypt application data and return sender and plaintext.

        Parameters:
            ciphertext_bytes: Encoded MLSCiphertext bytes.

        Returns:
            (sender_leaf_index, plaintext).
        """
        ct = decode_application(ciphertext_bytes)
        return self._group.unprotect(ct)

    # --- Exporter interface ---
    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export keying material from the current epoch (RFC 9420 exporter).

        Parameters:
            label: Export label (e.g. b"APP_KEY").
            context: Context bytes.
            length: Length in bytes of the derived secret.

        Returns:
            Derived secret of the requested length.
        """
        return self._group.export_secret(label, context, length)

    def get_resumption_psk(self) -> bytes:
        """Export current epoch resumption PSK."""
        return self._group.get_resumption_psk()

    def apply_policy(self, policy: "MLSAppPolicy") -> None:
        """Apply app-level runtime and credential policy to this session."""
        self._group.configure_runtime_policy(
            secret_tree_window_size=int(policy.secret_tree_window_size),
            max_generation_gap=int(policy.max_generation_gap),
            aead_limit_bytes=policy.aead_limit_bytes,
        )
        if policy.trust_roots:
            self._group.set_trust_roots(policy.trust_roots)
        if policy.x509_policy is not None:
            self._group.set_x509_policy(policy.x509_policy)

    def get_effective_policy(self) -> dict[str, int | None]:
        """Return effective runtime policy currently enforced by the group."""
        return self._group.get_runtime_policy()

    # --- Introspection ---
    @property
    def epoch(self) -> int:
        """Current epoch number."""
        return self._group.epoch

    @property
    def group_id(self) -> bytes:
        """Group identifier."""
        return self._group.group_id

    @property
    def member_count(self) -> int:
        """Number of members in the group."""
        return self._group.member_count

    @property
    def own_leaf_index(self) -> int:
        """This member's leaf index in the ratchet tree."""
        return self._group.own_leaf_index

    # --- Persistence ---
    def serialize(self) -> bytes:
        """Serialize the underlying group state for later resumption.

        Returns:
            Opaque bytes that can be passed to deserialize() with the same crypto/backend.
        """
        return self._group.to_bytes()

    @classmethod
    def deserialize(
        cls,
        data: bytes,
        crypto: CryptoProvider,
        policy: "MLSAppPolicy | None" = None,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "MLSGroupSession":
        """Restore a session from previously serialized group state.

        Parameters:
            data: Bytes from a previous serialize() call.
            crypto: Crypto provider (must match the group ciphersuite).
            tree_backend: Ratchet tree backend (should match original session).

        Returns:
            MLSGroupSession with restored group state.
        """
        group = Group.from_bytes(data, crypto, tree_backend=tree_backend)
        sess = cls(group)
        if policy is not None:
            sess.apply_policy(policy)
        return sess

    def close(self) -> None:
        """Best-effort cleanup hook for sensitive in-memory state."""
        self._group.close()


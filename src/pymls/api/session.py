from __future__ import annotations

from typing import Tuple, List

from ..mls.group import Group
from ..protocol.key_packages import KeyPackage, LeafNode
from ..protocol.data_structures import Welcome
from ..crypto.crypto_provider import CryptoProvider
from ..interop.wire import (
    encode_handshake,
    decode_handshake,
    encode_application,
    decode_application,
)
from ..protocol.messages import MLSPlaintext, MLSCiphertext


class MLSGroupSession:
    """
    Synchronous high-level session wrapper around `pymls.mls.Group`.

    Responsibilities:
    - Orchestrate group lifecycle (create/join, add/update/remove, commit/apply)
    - Provide byte-oriented handshake/application I/O
    - Expose exporter-based key derivation for applications

    This is general-purpose and not tied to any specific application protocol.

    Example:
        >>> from pymls.api import MLSGroupSession
        >>> from pymls import DefaultCryptoProvider
        >>> from pymls.protocol.key_packages import KeyPackage, LeafNode
        >>> from pymls.protocol.data_structures import Credential, Signature
        >>> from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
        >>> crypto = DefaultCryptoProvider()
        >>> # Build a minimal KeyPackage for the first member
        >>> sk_sig = ed25519.Ed25519PrivateKey.generate()
        >>> pk_sig = sk_sig.public_key()
        >>> sk_kem = x25519.X25519PrivateKey.generate()
        >>> pk_kem = sk_kem.public_key()
        >>> cred = Credential(identity=b"userA", public_key=pk_sig.public_bytes_raw())
        >>> leaf = LeafNode(encryption_key=pk_kem.public_bytes_raw(), signature_key=pk_sig.public_bytes_raw(), credential=cred, capabilities=b"", parent_hash=b"")
        >>> kp = KeyPackage(leaf_node=leaf, signature=Signature(crypto.sign_with_label(sk_sig.private_bytes_raw(), b"KeyPackageTBS", leaf.serialize())))
        >>> # Create a session and use exporter for application-defined keys
        >>> sess = MLSGroupSession.create(b"g1", kp, crypto)
        >>> key = sess.export_secret(b"APP_KEY", b"context", 32)
    """

    def __init__(self, group: Group):
        self._group = group

    # --- Construction ---
    @classmethod
    def create(cls, group_id: bytes, key_package: KeyPackage, crypto: CryptoProvider) -> "MLSGroupSession":
        return cls(Group.create(group_id, key_package, crypto))

    @classmethod
    def join_from_welcome(cls, welcome: Welcome, hpke_private_key: bytes, crypto: CryptoProvider) -> "MLSGroupSession":
        return cls(Group.join_from_welcome(welcome, hpke_private_key, crypto))

    # --- Handshake proposals and commits (byte I/O) ---
    def add_member(self, key_package: KeyPackage, signing_key: bytes) -> bytes:
        """Create an Add proposal, returning handshake bytes to send."""
        pt: MLSPlaintext = self._group.add(key_package, signing_key)
        return encode_handshake(pt)

    def update_self(self, leaf_node: LeafNode, signing_key: bytes) -> bytes:
        """Create an Update proposal for this member, returning handshake bytes to send."""
        pt: MLSPlaintext = self._group.update(leaf_node, signing_key)
        return encode_handshake(pt)

    def remove_member(self, removed_index: int, signing_key: bytes) -> bytes:
        """Create a Remove proposal, returning handshake bytes to send."""
        pt: MLSPlaintext = self._group.remove(removed_index, signing_key)
        return encode_handshake(pt)

    def process_proposal(self, handshake_bytes: bytes, sender_leaf_index: int) -> None:
        """Process a received proposal from sender at leaf index."""
        pt = decode_handshake(handshake_bytes)
        self._group.process_proposal(pt, sender_leaf_index)

    def commit(self, signing_key: bytes) -> Tuple[bytes, List[Welcome]]:
        """Create a Commit and corresponding Welcomes; returns (commit_bytes, welcomes)."""
        pt, welcomes = self._group.commit(signing_key)
        return encode_handshake(pt), welcomes

    def apply_commit(self, handshake_bytes: bytes, sender_leaf_index: int) -> None:
        """Apply a received Commit broadcast from the given sender index."""
        pt = decode_handshake(handshake_bytes)
        self._group.apply_commit(pt, sender_leaf_index)

    # --- Application data (byte I/O) ---
    def protect_application(self, plaintext: bytes) -> bytes:
        """Encrypt application data to MLSCiphertext bytes."""
        ct: MLSCiphertext = self._group.protect(plaintext)
        return encode_application(ct)

    def unprotect_application(self, ciphertext_bytes: bytes) -> Tuple[int, bytes]:
        """Decrypt MLSCiphertext bytes, returning (sender_leaf_index, plaintext)."""
        ct = decode_application(ciphertext_bytes)
        return self._group.unprotect(ct)

    # --- Exporter interface ---
    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export external keying material from the current epoch."""
        return self._group.export_secret(label, context, length)

    # --- Introspection ---
    @property
    def epoch(self) -> int:
        return self._group.epoch

    @property
    def group_id(self) -> bytes:
        return self._group.group_id

    @property
    def member_count(self) -> int:
        return self._group.member_count

    @property
    def own_leaf_index(self) -> int:
        return self._group.own_leaf_index

    # --- Persistence ---
    def serialize(self) -> bytes:
        """Serialize the underlying group state for later resumption."""
        return self._group.to_bytes()

    @classmethod
    def deserialize(cls, data: bytes, crypto: CryptoProvider) -> "MLSGroupSession":
        """Deserialize a session from serialized group state."""
        group = Group.from_bytes(data, crypto)
        return cls(group)


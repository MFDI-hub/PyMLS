from __future__ import annotations

from ..protocol.mls_group import MLSGroup as _ProtocolMLSGroup
from ..crypto.crypto_provider import CryptoProvider
from ..protocol.key_packages import KeyPackage, LeafNode
from ..protocol.data_structures import Sender
from ..protocol.messages import MLSPlaintext, MLSCiphertext
from ..protocol.data_structures import Welcome
from ..mls.exceptions import CommitValidationError


class Group:
    """
    Ergonomic wrapper around the protocol MLSGroup.

    Rationale:
    - Implements RFC 9420 group lifecycle interfaces, delegating to `protocol.MLSGroup`.
    - See RFC 9420 §8 (Group operations) and Appendix C/D (tree representations).
    """

    def __init__(self, inner: _ProtocolMLSGroup):
        self._inner = inner

    @classmethod
    def create(cls, group_id: bytes, key_package: KeyPackage, crypto: CryptoProvider) -> "Group":
        """Create a new Group with the initial member from a KeyPackage."""
        return cls(_ProtocolMLSGroup.create(group_id=group_id, key_package=key_package, crypto_provider=crypto))

    @classmethod
    def join_from_welcome(cls, welcome: Welcome, hpke_private_key: bytes, crypto: CryptoProvider) -> "Group":
        """Join an existing group using a Welcome and HPKE private key."""
        return cls(_ProtocolMLSGroup.from_welcome(welcome=welcome, hpke_private_key=hpke_private_key, crypto_provider=crypto))

    def add(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        """Create an Add proposal for the provided KeyPackage."""
        return self._inner.create_add_proposal(key_package, signing_key)

    def update(self, leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext:
        """Create an Update proposal with the provided LeafNode."""
        return self._inner.create_update_proposal(leaf_node, signing_key)

    def remove(self, removed_index: int, signing_key: bytes) -> MLSPlaintext:
        """Create a Remove proposal for the member at removed_index."""
        return self._inner.create_remove_proposal(removed_index, signing_key)

    def process_proposal(self, message: MLSPlaintext, sender_leaf_index: int) -> None:
        """Verify and enqueue a received proposal from sender_leaf_index."""
        return self._inner.process_proposal(message, Sender(sender_leaf_index))

    def commit(self, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create and return a Commit along with Welcome messages for additions."""
        return self._inner.create_commit(signing_key)

    def apply_commit(self, message: MLSPlaintext, sender_leaf_index: int) -> None:
        """Verify and apply a Commit from sender_leaf_index."""
        try:
            return self._inner.process_commit(message, sender_leaf_index)
        except CommitValidationError as e:
            # Convert to ValueError for compatibility with tests expecting ValueError
            raise ValueError(str(e)) from e

    def protect(self, application_data: bytes) -> MLSCiphertext:
        """Encrypt application_data as MLSCiphertext for this group."""
        return self._inner.protect(application_data)

    def unprotect(self, message: MLSCiphertext) -> tuple[int, bytes]:
        """Decrypt MLSCiphertext and return (sender_leaf_index, plaintext)."""
        return self._inner.unprotect(message)

    @property
    def epoch(self) -> int:
        """Current group epoch."""
        return self._inner.get_epoch()

    @property
    def group_id(self) -> bytes:
        """Group identifier."""
        return self._inner.get_group_id()


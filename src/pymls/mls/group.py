from __future__ import annotations

from ..protocol.mls_group import MLSGroup as _ProtocolMLSGroup
from ..crypto.crypto_provider import CryptoProvider
from ..protocol.key_packages import KeyPackage, LeafNode
from ..protocol.data_structures import Sender
from ..protocol.messages import MLSPlaintext, MLSCiphertext
from ..protocol.data_structures import Welcome


class Group:
    """
    Ergonomic wrapper around the protocol MLSGroup.
    """

    def __init__(self, inner: _ProtocolMLSGroup):
        self._inner = inner

    @classmethod
    def create(cls, group_id: bytes, key_package: KeyPackage, crypto: CryptoProvider) -> "Group":
        return cls(_ProtocolMLSGroup.create(group_id=group_id, key_package=key_package, crypto_provider=crypto))

    @classmethod
    def join_from_welcome(cls, welcome: Welcome, hpke_private_key: bytes, crypto: CryptoProvider) -> "Group":
        return cls(_ProtocolMLSGroup.from_welcome(welcome=welcome, hpke_private_key=hpke_private_key, crypto_provider=crypto))

    def add(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        return self._inner.create_add_proposal(key_package, signing_key)

    def update(self, leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext:
        return self._inner.create_update_proposal(leaf_node, signing_key)

    def remove(self, removed_index: int, signing_key: bytes) -> MLSPlaintext:
        return self._inner.create_remove_proposal(removed_index, signing_key)

    def process_proposal(self, message: MLSPlaintext, sender_leaf_index: int) -> None:
        return self._inner.process_proposal(message, Sender(sender_leaf_index))

    def commit(self, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        return self._inner.create_commit(signing_key)

    def apply_commit(self, message: MLSPlaintext, sender_leaf_index: int) -> None:
        return self._inner.process_commit(message, sender_leaf_index)

    def protect(self, application_data: bytes) -> MLSCiphertext:
        return self._inner.protect(application_data)

    def unprotect(self, message: MLSCiphertext) -> tuple[int, bytes]:
        return self._inner.unprotect(message)

    @property
    def epoch(self) -> int:
        return self._inner.get_epoch()

    @property
    def group_id(self) -> bytes:
        return self._inner.get_group_id()


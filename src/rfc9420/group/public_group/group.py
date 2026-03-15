"""PublicGroup: passive observer view (no secret keys, tree and commit validation only)."""
from __future__ import annotations

from typing import Union, Any

from ...group.mls_group.processing import MLSGroup as _ProtocolMLSGroup
from ...messages.data_structures import GroupInfo, GroupContext
from ...messages.messages import MLSPlaintext
from ...protocol.validations import validate_commit_basic
from ...protocol.tree.ratchet_tree_backend import DEFAULT_TREE_BACKEND
from ...crypto.crypto_provider import CryptoProvider


class PublicGroup:
    """Passive observer: tracks public ratchet tree and group context, validates handshake.

    No SecretTree or key schedule; cannot decrypt application messages. Use for
    Delivery Service or other parties that need to validate commits and track
    membership without private keys.
    """

    def __init__(
        self,
        crypto_provider: CryptoProvider,
        group_context: GroupContext,
        inner: _ProtocolMLSGroup,
    ) -> None:
        self._crypto = crypto_provider
        self._group_context = group_context
        self._inner = inner

    @property
    def group_id(self) -> bytes:
        return self._group_context.group_id

    @property
    def epoch(self) -> int:
        return self._group_context.epoch

    @property
    def member_count(self) -> int:
        return self._inner.get_member_count()

    def get_leaf_node(self, leaf_index: int) -> Any:
        """Return the leaf node at the given index (public key material only)."""
        node = self._inner._ratchet_tree.get_node(leaf_index * 2)
        return node.leaf_node if node else None

    @classmethod
    def from_group_info(
        cls,
        crypto_provider: CryptoProvider,
        group_info: Union[GroupInfo, bytes],
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "PublicGroup":
        """Build a PublicGroup from GroupInfo (e.g. from decrypted Welcome).

        Verifies GroupInfo signature and loads the public ratchet tree from
        extensions. No key schedule or secret tree is created.
        """
        if isinstance(group_info, bytes):
            gi = GroupInfo.deserialize(group_info)
        else:
            gi = group_info

        crypto_provider.set_ciphersuite(gi.group_context.cipher_suite_id)
        inner = _ProtocolMLSGroup.from_group_info(
            gi,
            crypto_provider,
            secret_tree_window_size=0,
            max_generation_gap=0,
            tree_backend=tree_backend,
        )
        return cls(crypto_provider, gi.group_context, inner)

    def process_handshake(self, plaintext: MLSPlaintext) -> None:
        """Validate a handshake message (signature and commit structure); do not update state.

        Verifies the sender's signature. Does not verify membership tag (no key schedule).
        Validates commit basic structure if content is a commit. Raises on failure.
        """
        from ...messages.data_structures import Commit
        from ...messages.messages import verify_plaintext, ContentType
        from ...mls.exceptions import InvalidSignatureError

        fc = plaintext.auth_content.tbs.framed_content
        sender_leaf_index = fc.sender.sender
        sender_node = self._inner._ratchet_tree.get_node(sender_leaf_index * 2)
        if not sender_node or not sender_node.leaf_node:
            raise InvalidSignatureError("no leaf node for sender")
        sender_signature_key = sender_node.leaf_node.signature_key
        gc_bytes = self._group_context.serialize() if self._group_context else None
        verify_plaintext(
            plaintext,
            sender_signature_key,
            membership_key=None,
            crypto=self._crypto,
            group_context=gc_bytes,
        )
        if fc.content_type == ContentType.COMMIT:
            commit = Commit.deserialize(fc.content)
            validate_commit_basic(commit)

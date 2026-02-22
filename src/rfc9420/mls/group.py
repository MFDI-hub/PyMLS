from __future__ import annotations

from ..protocol.mls_group import MLSGroup as _ProtocolMLSGroup
from ..protocol.ratchet_tree_backend import DEFAULT_TREE_BACKEND
from ..crypto.crypto_provider import CryptoProvider
from ..protocol.key_packages import KeyPackage, LeafNode
from ..protocol.data_structures import Sender
from ..protocol.messages import MLSPlaintext, MLSCiphertext
from ..protocol.data_structures import Welcome
from ..mls.exceptions import CommitValidationError


class Group:
    """High-level API for MLS group operations (RFC 9420).

    Ergonomic wrapper around the protocol-level MLSGroup: create/join groups,
    add/update/remove members, commit, and protect/unprotect application data.
    See RFC 9420 §8 (Group operations) and Appendix C/D (tree representations).

    Parameters:
        inner: The underlying protocol MLSGroup instance.
    """

    def __init__(self, inner: _ProtocolMLSGroup):
        """Initialize a Group wrapper around a protocol MLSGroup."""
        self._inner = inner

    @classmethod
    def create(
        cls,
        group_id: bytes,
        key_package: KeyPackage,
        crypto: CryptoProvider,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "Group":
        """Create a new MLS group with an initial member.

        Creates a new group with epoch 0, initializes the ratchet tree with the
        provided key package, and derives initial group secrets.

        Args:
            group_id: Application-chosen identifier for the group.
            key_package: KeyPackage of the initial member to add.
            crypto: CryptoProvider instance for cryptographic operations.

        Returns:
            A new Group instance with the initial member.

        Raises:
            RFC9420Error: If group creation fails.
        """
        return cls(
            _ProtocolMLSGroup.create(
                group_id=group_id,
                key_package=key_package,
                crypto_provider=crypto,
                tree_backend=tree_backend,
            )
        )

    @classmethod
    def join_from_welcome(
        cls,
        welcome: Welcome,
        hpke_private_key: bytes,
        crypto: CryptoProvider,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "Group":
        """Join an existing group using a Welcome message.

        Processes a Welcome message received out-of-band, decrypts the GroupInfo,
        verifies signatures, and initializes group state.

        Args:
            welcome: Welcome message containing encrypted group secrets.
            hpke_private_key: HPKE private key for decrypting EncryptedGroupSecrets.
            crypto: CryptoProvider instance for cryptographic operations.

        Returns:
            A new Group instance initialized from the Welcome.

        Raises:
            CommitValidationError: If no EncryptedGroupSecrets can be opened.
            InvalidSignatureError: If GroupInfo signature verification fails.
        """
        return cls(
            _ProtocolMLSGroup.from_welcome(
                welcome=welcome,
                hpke_private_key=hpke_private_key,
                crypto_provider=crypto,
                tree_backend=tree_backend,
            )
        )

    def add(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        """Create an Add proposal to add a new member to the group.

        Args:
            key_package: KeyPackage of the member to add.
            signing_key: Private signing key for authenticating the proposal.

        Returns:
            MLSPlaintext containing the Add proposal.

        Raises:
            CommitValidationError: If the KeyPackage is invalid.
        """
        return self._inner.create_add_proposal(key_package, signing_key)

    def update(self, leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext:
        """Create an Update proposal to refresh the sender's leaf node.

        Args:
            leaf_node: New LeafNode with updated keys.
            signing_key: Private signing key for authenticating the proposal.

        Returns:
            MLSPlaintext containing the Update proposal.
        """
        return self._inner.create_update_proposal(leaf_node, signing_key)

    def remove(self, removed_index: int, signing_key: bytes) -> MLSPlaintext:
        """Create a Remove proposal to remove a member from the group.

        Args:
            removed_index: Leaf index of the member to remove.
            signing_key: Private signing key for authenticating the proposal.

        Returns:
            MLSPlaintext containing the Remove proposal.
        """
        return self._inner.create_remove_proposal(removed_index, signing_key)

    def process_proposal(self, message: MLSPlaintext, sender_leaf_index: int) -> None:
        """Verify and enqueue a received proposal.

        Verifies the proposal's signature and membership tag, validates credentials
        if applicable, and caches it for inclusion in a future commit.

        Args:
            message: MLSPlaintext containing the proposal.
            sender_leaf_index: Leaf index of the proposal sender.

        Raises:
            CommitValidationError: If verification fails or sender is invalid.
            InvalidSignatureError: If signature or membership tag verification fails.
        """
        return self._inner.process_proposal(message, Sender(sender_leaf_index))

    def commit(self, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]:
        """Create a commit with all pending proposals.

        Creates a commit message that includes all pending proposals, generates
        an update path if needed, and produces Welcome messages for new members.

        Args:
            signing_key: Private signing key for authenticating the commit.

        Returns:
            Tuple of (commit MLSPlaintext, list of Welcome messages for new members).

        Raises:
            RFC9420Error: If group is not initialized or commit creation fails.
        """
        return self._inner.create_commit(signing_key)

    def apply_commit(self, message: MLSPlaintext, sender_leaf_index: int) -> None:
        """Verify and apply a received commit.

        Verifies the commit's signature and membership tag, validates proposal
        references, applies changes to the ratchet tree, and updates group state.

        Args:
            message: MLSPlaintext containing the commit.
            sender_leaf_index: Leaf index of the commit sender.

        Raises:
            ValueError: If commit validation fails (converted from CommitValidationError).
        """
        try:
            if sender_leaf_index < 0 or sender_leaf_index >= self._inner.get_member_count():
                raise ValueError(f"invalid sender leaf index: {sender_leaf_index}")
            # A joiner restored from Welcome may already be at the post-commit
            # epoch. Treat stale commit re-application as a no-op.
            msg_epoch = message.auth_content.tbs.framed_content.epoch
            if msg_epoch < self._inner.get_epoch():
                return None
            return self._inner.process_commit(message, sender_leaf_index)
        except CommitValidationError as e:
            # Convert to ValueError for compatibility with tests expecting ValueError
            raise ValueError(str(e)) from e

    def protect(self, application_data: bytes) -> MLSCiphertext:
        """Encrypt application data for this group.

        Encrypts application data using the current epoch's application secret
        and the secret tree.

        Args:
            application_data: Plaintext application data to encrypt.

        Returns:
            MLSCiphertext containing the encrypted data.

        Raises:
            RFC9420Error: If group is not initialized or a commit is pending.
        """
        return self._inner.protect(application_data)

    def unprotect(self, message: MLSCiphertext) -> tuple[int, bytes]:
        """Decrypt application ciphertext.

        Decrypts MLSCiphertext using the secret tree and returns the sender
        index and plaintext.

        Args:
            message: MLSCiphertext to decrypt.

        Returns:
            Tuple of (sender_leaf_index, plaintext).

        Raises:
            RFC9420Error: If decryption fails or group is not initialized.
        """
        out = self._inner.unprotect(message)
        if isinstance(out, tuple) and len(out) >= 2:
            return int(out[0]), out[1]
        raise ValueError("unexpected unprotect return shape")

    @property
    def epoch(self) -> int:
        """Current group epoch.

        Returns:
            The current epoch number (starts at 0).
        """
        return self._inner.get_epoch()

    @property
    def group_id(self) -> bytes:
        """Group identifier.

        Returns:
            The group identifier bytes.
        """
        return self._inner.get_group_id()

    # --- Added high-level exports and properties ---
    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export external keying material using the MLS exporter."""
        return self._inner.export_secret(label, context, length)

    @property
    def exporter_secret(self) -> bytes:
        """Current epoch exporter secret."""
        return self._inner.get_exporter_secret()

    @property
    def encryption_secret(self) -> bytes:
        """Current epoch encryption secret (root of SecretTree)."""
        return self._inner.get_encryption_secret()

    @property
    def own_leaf_index(self) -> int:
        """Local member's leaf index."""
        return self._inner.get_own_leaf_index()

    @property
    def member_count(self) -> int:
        """Number of members (leaves) in the group."""
        return self._inner.get_member_count()

    # --- Persistence passthroughs ---
    def to_bytes(self) -> bytes:
        """Serialize the group state."""
        return self._inner.to_bytes()

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        crypto: CryptoProvider,
        tree_backend: str = DEFAULT_TREE_BACKEND,
    ) -> "Group":
        """Deserialize group state into a Group instance."""
        return cls(_ProtocolMLSGroup.from_bytes(data, crypto, tree_backend=tree_backend))


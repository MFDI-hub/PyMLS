"""Active MLSGroup API: staged commits and config-driven providers."""
from __future__ import annotations

from typing import Optional

from .processing import MLSGroup as _ProtocolMLSGroup, PendingCommit
from ...messages.key_packages import KeyPackage, LeafNode
from ...messages.data_structures import Welcome
from ...messages.messages import MLSPlaintext, MLSCiphertext, ContentType
from ...providers.config import GroupConfig
from ...mls.exceptions import InvalidCommitError
from .staged_commit import StagedCommit


def get_commit_sender_leaf_index(commit_bytes: bytes) -> int:
    """Return the leaf index of the commit sender from serialized commit plaintext.

    Parameters
    ----------
    commit_bytes : bytes
        Serialized MLSPlaintext (Commit).

    Returns
    -------
    int
        Sender leaf index.

    Raises
    ------
    InvalidCommitError
        If deserialization fails or message is not a Commit.
    """
    try:
        msg = MLSPlaintext.deserialize(commit_bytes)
    except Exception as e:
        raise InvalidCommitError(f"failed to deserialize commit: {e}") from e
    ct = msg.auth_content.tbs.framed_content.content_type
    if ct != ContentType.COMMIT:
        raise InvalidCommitError("message is not a commit")
    return msg.auth_content.tbs.framed_content.sender.sender


class MLSGroup:
    """High-level active member API: staged commits, no immediate mutation on commit.

    create_commit() returns a StagedCommit; call staged_commit.merge(config.storage_provider)
    to persist, then apply_staged_commit(staged_commit) to update in-memory state.

    Parameters
    ----------
    config : GroupConfig
        Providers and settings for the group.
    inner : _ProtocolMLSGroup
        Low-level protocol group state.
    """

    def __init__(self, config: GroupConfig, inner: _ProtocolMLSGroup) -> None:
        self._config = config
        self._inner = inner

    @property
    def config(self) -> GroupConfig:
        return self._config

    @classmethod
    def create(
        cls,
        config: GroupConfig,
        group_id: bytes,
        key_package: KeyPackage,
        initial_extensions: bytes = b"",
    ) -> "MLSGroup":
        """Create a new MLS group with an initial member.

        Parameters
        ----------
        config : GroupConfig
            Providers and settings.
        group_id : bytes
            Group identifier.
        key_package : KeyPackage
            Creator's key package.
        initial_extensions : bytes, optional
            Initial group context extensions (default b"").

        Returns
        -------
        MLSGroup
            New group with creator as sole member.
        """
        inner = _ProtocolMLSGroup.create(
            group_id=group_id,
            key_package=key_package,
            crypto_provider=config.crypto_provider,
            rand_provider=config.resolved_rand_provider(),
            secret_tree_window_size=config.secret_tree_window_size,
            max_generation_gap=config.max_generation_gap,
            aead_limit_bytes=config.aead_limit_bytes,
            tree_backend=config.tree_backend_id,
            initial_extensions=initial_extensions,
        )
        if config.identity_provider is not None:
            inner.set_credential_validator(config.identity_provider.validate_credential)
        return cls(config, inner)

    @classmethod
    def join_from_welcome(
        cls,
        config: GroupConfig,
        welcome: Welcome,
        hpke_private_key: bytes,
        key_package: Optional[KeyPackage] = None,
    ) -> "MLSGroup":
        """Join an existing group using a Welcome message.

        Parameters
        ----------
        config : GroupConfig
            Providers and settings.
        welcome : Welcome
            Welcome message from the group.
        hpke_private_key : bytes
            Private key for the key package in the welcome.
        key_package : Optional[KeyPackage], optional
            Local key package if not in welcome (default None).

        Returns
        -------
        MLSGroup
            Joined group state.

        Raises
        ------
        InvalidWelcomeError
            If welcome cannot be processed.
        """
        from ...mls.exceptions import InvalidWelcomeError
        from ...mls.exceptions import CommitValidationError
        from ...messages.messages import InvalidSignatureError

        credential_validator = None
        if config.identity_provider is not None:
            credential_validator = config.identity_provider.validate_credential
        try:
            inner = _ProtocolMLSGroup.from_welcome(
                welcome=welcome,
                hpke_private_key=hpke_private_key,
                crypto_provider=config.crypto_provider,
                rand_provider=config.resolved_rand_provider(),
                secret_tree_window_size=config.secret_tree_window_size,
                max_generation_gap=config.max_generation_gap,
                aead_limit_bytes=config.aead_limit_bytes,
                tree_backend=config.tree_backend_id,
                key_package=key_package,
                credential_validator=credential_validator,
            )
            return cls(config, inner)
        except (CommitValidationError, InvalidSignatureError) as e:
            raise InvalidWelcomeError(str(e)) from e

    @classmethod
    def from_bytes(cls, config: GroupConfig, data: bytes) -> "MLSGroup":
        """Deserialize group state into an MLSGroup instance.

        Uses config.crypto_provider and config.tree_backend_id. If
        config.identity_provider is set, it is wired to the inner group.

        Parameters
        ----------
        config : GroupConfig
            Same providers as when state was serialized.
        data : bytes
            Bytes from a previous serialize (inner.to_bytes()).

        Returns
        -------
        MLSGroup
            Restored group state.
        """
        inner = _ProtocolMLSGroup.from_bytes(
            data,
            config.crypto_provider,
            rand_provider=config.resolved_rand_provider(),
            tree_backend=config.tree_backend_id,
        )
        if config.identity_provider is not None:
            inner.set_credential_validator(config.identity_provider.validate_credential)
        return cls(config, inner)

    def create_commit(
        self,
        signing_key: bytes,
        return_per_joiner_welcomes: bool = False,
    ) -> StagedCommit:
        """Create a commit over pending proposals; do NOT mutate state.

        Returns a StagedCommit. Persist with staged_commit.merge(config.storage_provider),
        then apply in-memory with apply_staged_commit(staged_commit).
        """
        pending = self._inner.create_commit(signing_key, return_per_joiner_welcomes)
        prior_epoch = self._inner.get_epoch()
        return StagedCommit(
            commit_message=pending.commit_message,
            welcomes=pending.welcomes,
            new_epoch_state=pending.new_epoch_state,
            prior_epoch=prior_epoch,
            group_id=self._inner.get_group_id(),
            own_leaf_index=self._inner.get_own_leaf_index(),
            tree_backend_id=self._config.tree_backend_id,
        )

    def apply_staged_commit(self, staged: StagedCommit) -> None:
        """Apply a StagedCommit to in-memory state (after merge or when loading)."""
        pending = PendingCommit(
            staged.commit_message,
            staged.welcomes,
            staged.new_epoch_state,
        )
        self._inner.apply_own_commit(pending)

    def add(self, key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext:
        return self._inner.create_add_proposal(key_package, signing_key)

    def update(self, leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext:
        return self._inner.create_update_proposal(leaf_node, signing_key)

    def remove(self, removed_index: int, signing_key: bytes) -> MLSPlaintext:
        return self._inner.create_remove_proposal(removed_index, signing_key)

    def process_proposal(
        self, message: MLSPlaintext, sender_leaf_index: int, sender_type: int = 1
    ) -> None:
        from ...messages.data_structures import Sender, SenderType
        self._inner.process_proposal(
            message, Sender(sender_leaf_index, SenderType(sender_type))
        )

    def process_commit(self, message: MLSPlaintext, sender_leaf_index: Optional[int] = None) -> None:
        """Process a received commit and update in-memory state (mutating). Compatibility path."""
        if sender_leaf_index is None:
            sender_leaf_index = get_commit_sender_leaf_index(message.serialize())
        self._inner.process_commit(message, sender_leaf_index)

    def process_commit_staged(
        self, message: MLSPlaintext, sender_leaf_index: Optional[int] = None
    ) -> StagedCommit:
        """Process a received commit and return a StagedCommit without mutating state.

        Caller should: staged = process_commit_staged(...); await staged.merge(config.storage_provider);
        then apply_staged_commit(staged).
        """
        if sender_leaf_index is None:
            sender_leaf_index = get_commit_sender_leaf_index(message.serialize())
        commit_message, welcomes, new_epoch_state = self._inner.process_commit_staged(
            message, sender_leaf_index, self._config.tree_backend_id
        )
        return StagedCommit(
            commit_message=commit_message,
            welcomes=welcomes,
            new_epoch_state=new_epoch_state,
            prior_epoch=self._inner.get_epoch(),
            group_id=self._inner.get_group_id(),
            own_leaf_index=self._inner.get_own_leaf_index(),
            tree_backend_id=self._config.tree_backend_id,
        )

    def revoke_proposal(self, proposal_ref: bytes) -> None:
        self._inner.revoke_proposal(proposal_ref)

    def protect(self, application_data: bytes, signing_key: Optional[bytes] = None) -> MLSCiphertext:
        return self._inner.protect(application_data, signing_key=signing_key)

    def unprotect(self, message: MLSCiphertext) -> tuple[int, bytes]:
        out = self._inner.unprotect(message)
        if isinstance(out, tuple) and len(out) >= 2:
            return int(out[0]), out[1]
        raise ValueError("unexpected unprotect return shape")

    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        return self._inner.export_secret(label, context, length)

    def get_resumption_psk(self) -> bytes:
        return self._inner.get_resumption_psk()

    @property
    def epoch(self) -> int:
        return self._inner.get_epoch()

    @property
    def group_id(self) -> bytes:
        return self._inner.get_group_id()

    @property
    def own_leaf_index(self) -> int:
        return self._inner.get_own_leaf_index()

    @property
    def member_count(self) -> int:
        return self._inner.get_member_count()

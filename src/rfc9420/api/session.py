from __future__ import annotations

import asyncio
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING

from ..group.mls_group.group import MLSGroup
from ..messages.key_packages import KeyPackage, LeafNode
from ..messages.data_structures import Welcome
from ..interop.wire import (
    encode_handshake,
    decode_handshake,
    encode_application,
    decode_application,
)
from ..messages.messages import MLSPlaintext, MLSCiphertext
from ..providers.config import GroupConfig

if TYPE_CHECKING:
    from .policy import MLSAppPolicy


def _run_async(coro):
    """Run async coroutine from sync context (e.g. merge).

    Parameters
    ----------
    coro : coroutine
        Async coroutine to run.

    Returns
    -------
    Any
        Result of the coroutine.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    return asyncio.run(coro)


class MLSGroupSession:
    """Synchronous high-level session wrapper around config-driven MLSGroup.

    Orchestrates group lifecycle (create/join, add/update/remove, commit/apply),
    provides byte-oriented handshake and application I/O, and exposes
    exporter-based key derivation. Not tied to any specific application protocol.

    Parameters
    ----------
    group : MLSGroup
        An MLSGroup instance (from create_with_config, join_from_welcome_with_config,
        or deserialize_with_config).
    """

    def __init__(self, group: MLSGroup):
        """Initialize the session with a config-driven MLSGroup.

        Parameters
        ----------
        group : MLSGroup
            Config-driven MLSGroup to wrap.
        """
        self._group = group

    # --- Construction ---
    @classmethod
    def create_with_config(
        cls,
        config: GroupConfig,
        group_id: bytes,
        key_package: KeyPackage,
        initial_extensions: bytes = b"",
    ) -> "MLSGroupSession":
        """Create a new MLS group and session using GroupConfig (config-driven, staged commits).

        Uses config.crypto_provider, config.storage_provider, config.identity_provider.
        Commit flow: create_commit -> merge(storage) -> apply_staged_commit.

        Parameters
        ----------
        config : GroupConfig
            Providers and settings for the group.
        group_id : bytes
            Group identifier.
        key_package : KeyPackage
            Creator's key package.
        initial_extensions : bytes, optional
            Initial group context extensions (default b"").

        Returns
        -------
        MLSGroupSession
            New session for the created group.
        """
        mls_group = MLSGroup.create(
            config, group_id, key_package, initial_extensions=initial_extensions
        )
        return cls(mls_group)

    @classmethod
    def join_from_welcome_with_config(
        cls,
        config: GroupConfig,
        welcome: Welcome,
        hpke_private_key: bytes,
        key_package: Optional[KeyPackage] = None,
    ) -> "MLSGroupSession":
        """Join an existing group using GroupConfig (config-driven, identity provider wired).

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
        MLSGroupSession
            Session for the joined group.
        """
        mls_group = MLSGroup.join_from_welcome(
            config, welcome, hpke_private_key, key_package=key_package
        )
        return cls(mls_group)

    @classmethod
    def deserialize_with_config(
        cls,
        config: GroupConfig,
        data: bytes,
    ) -> "MLSGroupSession":
        """Restore a session from previously serialized group state.

        Parameters
        ----------
        config : GroupConfig
            GroupConfig with same crypto_provider and tree_backend_id as original session.
        data : bytes
            Bytes from a previous serialize() call.

        Returns
        -------
        MLSGroupSession
            Session with restored group state.
        """
        mls_group = MLSGroup.from_bytes(config, data)
        return cls(mls_group)

    # --- Handshake proposals and commits (byte I/O) ---
    def add_member(self, key_package: KeyPackage, signing_key: bytes) -> bytes:
        """Create an Add proposal for a new member.

        Parameters
        ----------
        key_package : KeyPackage
            Key package of the member to add.
        signing_key : bytes
            Signing key for the proposal.

        Returns
        -------
        bytes
            Handshake bytes (MLSPlaintext) to send to the group.
        """
        pt: MLSPlaintext = self._group.add(key_package, signing_key)
        return encode_handshake(pt)

    def update_self(self, leaf_node: LeafNode, signing_key: bytes) -> bytes:
        """Create an Update proposal for this member's leaf.

        Parameters
        ----------
        leaf_node : LeafNode
            New leaf node (e.g. new keys/capabilities).
        signing_key : bytes
            Signing key for the proposal.

        Returns
        -------
        bytes
            Handshake bytes to send to the group.
        """
        pt: MLSPlaintext = self._group.update(leaf_node, signing_key)
        return encode_handshake(pt)

    def remove_member(self, removed_index: int, signing_key: bytes) -> bytes:
        """Create a Remove proposal for the member at the given leaf index.

        Parameters
        ----------
        removed_index : int
            Leaf index of the member to remove.
        signing_key : bytes
            Signing key for the proposal.

        Returns
        -------
        bytes
            Handshake bytes to send to the group.
        """
        pt: MLSPlaintext = self._group.remove(removed_index, signing_key)
        return encode_handshake(pt)

    def process_proposal(self, handshake_bytes: bytes, sender_leaf_index: int) -> None:
        """Process a received proposal and update internal state.

        Parameters
        ----------
        handshake_bytes : bytes
            Encoded MLSPlaintext (proposal).
        sender_leaf_index : int
            Leaf index of the sender.
        """
        pt = decode_handshake(handshake_bytes)
        self._group.process_proposal(pt, sender_leaf_index)

    def revoke_proposal(self, proposal_ref: bytes) -> None:
        """Remove a cached proposal by its ProposalRef (e.g. when the delivery service revokes it).

        If the proposal_ref is not in the cache, this is a no-op.

        Parameters
        ----------
        proposal_ref : bytes
            ProposalRef (hash of the proposal per RFC 9420 §5.2).
        """
        self._group.revoke_proposal(proposal_ref)

    def commit(
        self,
        signing_key: bytes,
        return_per_joiner_welcomes: bool = False,
    ) -> Tuple[bytes, List[Welcome]]:
        """Create a Commit covering all pending proposals and generate Welcomes.

        Parameters
        ----------
        signing_key : bytes
            Signing key for the Commit.
        return_per_joiner_welcomes : bool, optional
            If True, return one Welcome per added member (each with a single
            EncryptedGroupSecrets), e.g. for DAVE voice gateway (default False).

        Returns
        -------
        Tuple[bytes, List[Welcome]]
            (commit_handshake_bytes, list of Welcome messages for new members).
        """
        staged = self._group.create_commit(signing_key, return_per_joiner_welcomes)
        _run_async(staged.merge(self._group.config.storage_provider))
        self._group.apply_staged_commit(staged)
        return encode_handshake(staged.commit_message), staged.welcomes

    def apply_commit(self, handshake_bytes: bytes, sender_leaf_index: int) -> None:
        """Apply a received Commit and update group state.

        Parameters
        ----------
        handshake_bytes : bytes
            Encoded MLSPlaintext (Commit).
        sender_leaf_index : int
            Leaf index of the committer.
        """
        pt = decode_handshake(handshake_bytes)
        self._group.process_commit(pt, sender_leaf_index)

    # --- Application data (byte I/O) ---
    def protect_application(self, plaintext: bytes, signing_key: Optional[bytes] = None) -> bytes:
        """Encrypt application data for the group.

        Parameters
        ----------
        plaintext : bytes
            Application message to encrypt.
        signing_key : Optional[bytes], optional
            Optional member leaf signature key for RFC 9420 §6.1 signing (default None).

        Returns
        -------
        bytes
            Encoded MLSCiphertext bytes.
        """
        ct: MLSCiphertext = self._group.protect(plaintext, signing_key=signing_key)
        return encode_application(ct)

    def unprotect_application(self, ciphertext_bytes: bytes) -> Tuple[int, bytes]:
        """Decrypt application data and return sender and plaintext.

        Parameters
        ----------
        ciphertext_bytes : bytes
            Encoded MLSCiphertext bytes.

        Returns
        -------
        Tuple[int, bytes]
            (sender_leaf_index, plaintext).
        """
        ct = decode_application(ciphertext_bytes)
        return self._group.unprotect(ct)

    # --- Exporter interface ---
    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export keying material from the current epoch (RFC 9420 exporter).

        Parameters
        ----------
        label : bytes
            Export label (e.g. b"APP_KEY").
        context : bytes
            Context bytes.
        length : int
            Length in bytes of the derived secret.

        Returns
        -------
        bytes
            Derived secret of the requested length.
        """
        return self._group.export_secret(label, context, length)

    def get_resumption_psk(self) -> bytes:
        """Export current epoch resumption PSK.

        Returns
        -------
        bytes
            Resumption PSK for the current epoch.
        """
        return self._group.get_resumption_psk()

    def apply_policy(self, policy: "MLSAppPolicy") -> None:
        """Apply app-level runtime and credential policy to this session.

        Parameters
        ----------
        policy : MLSAppPolicy
            App-level policy (secret tree window, generation gap, AEAD limit, trust roots, X.509).
        """
        self._group._inner.configure_runtime_policy(
            secret_tree_window_size=int(policy.secret_tree_window_size),
            max_generation_gap=int(policy.max_generation_gap),
            aead_limit_bytes=policy.aead_limit_bytes,
        )
        if policy.trust_roots:
            self._group._inner.set_trust_roots(policy.trust_roots)
        if policy.x509_policy is not None:
            self._group._inner.set_x509_policy(policy.x509_policy)

    def get_effective_policy(self) -> Dict[str, Optional[int]]:
        """Return effective runtime policy currently enforced by the group.

        Returns
        -------
        Dict[str, Optional[int]]
            Effective runtime policy (secret_tree_window_size, max_generation_gap, aead_limit_bytes).
        """
        return self._group._inner.get_runtime_policy()

    # --- Introspection ---
    @property
    def epoch(self) -> int:
        """Current epoch number.

        Returns
        -------
        int
            Current epoch number.
        """
        return self._group.epoch

    @property
    def group_id(self) -> bytes:
        """Group identifier.

        Returns
        -------
        bytes
            Group identifier.
        """
        return self._group.group_id

    @property
    def member_count(self) -> int:
        """Number of members in the group.

        Returns
        -------
        int
            Number of members in the group.
        """
        return self._group.member_count

    @property
    def own_leaf_index(self) -> int:
        """This member's leaf index in the ratchet tree.

        Returns
        -------
        int
            Own leaf index.
        """
        return self._group.own_leaf_index

    # --- Persistence ---
    def serialize(self) -> bytes:
        """Serialize the underlying group state for later resumption.

        Returns:
            Opaque bytes that can be passed to deserialize_with_config() with the same GroupConfig.
        """
        return self._group._inner.to_bytes()

    def close(self) -> None:
        """Best-effort cleanup hook for sensitive in-memory state.

        Returns
        -------
        None
        """
        self._group._inner.close()

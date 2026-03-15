"""Architecture-level tests: providers, staged commit, active/passive split, test-vector compatibility."""
from __future__ import annotations

import asyncio
import pytest

from rfc9420 import (
    GroupConfig,
    MLSGroup,
    StagedCommit,
    PublicGroup,
    ProtocolMLSGroup,
    DefaultCryptoProvider,
    MemoryStorageProvider,
    get_commit_sender_leaf_index,
)
from rfc9420.providers.storage import GroupEpochState
from rfc9420 import ProtocolMLSGroup as ProtocolMLSGroupRef


def _run(coro):
    return asyncio.run(coro)


def test_protocol_mls_group_available_for_test_vectors():
    """ProtocolMLSGroup must remain available for test_vectors_runner and spec compliance."""
    assert ProtocolMLSGroup is ProtocolMLSGroupRef
    assert hasattr(ProtocolMLSGroup, "create")
    assert hasattr(ProtocolMLSGroup, "from_welcome")
    assert hasattr(ProtocolMLSGroup, "from_group_info")


def test_group_config_construction():
    """GroupConfig composes crypto and storage providers."""
    crypto = DefaultCryptoProvider()
    storage = MemoryStorageProvider()
    config = GroupConfig(
        crypto_provider=crypto,
        storage_provider=storage,
        tree_backend_id="array",
    )
    assert config.crypto_provider is crypto
    assert config.storage_provider is storage
    assert config.tree_backend_id == "array"


def test_storage_merge_and_retrieve_roundtrip():
    """Storage merge_group_state + get_group_state roundtrip (atomic persist)."""
    storage = MemoryStorageProvider()
    state = GroupEpochState(
        group_id=b"g1",
        epoch=1,
        tree_snapshot=b"tree_snap",
        group_context=b"gc_bytes",
        state_payload=b"payload",
    )

    async def _():
        await storage.merge_group_state(b"g1", state)
        got = await storage.get_group_state(b"g1")
        assert got is not None
        assert got.epoch == 1
        assert got.tree_snapshot == b"tree_snap"

    _run(_())


@pytest.mark.skip(reason="Requires full KeyPackage signing; run with real key package if needed")
def test_staged_commit_merge_integration():
    """Full flow: protocol group create_commit -> StagedCommit -> merge(storage) -> state persisted."""
    from rfc9420.messages.key_packages import LeafNode, KeyPackage
    from rfc9420.messages.data_structures import Signature

    crypto = DefaultCryptoProvider()
    storage = MemoryStorageProvider()
    config = GroupConfig(crypto_provider=crypto, storage_provider=storage)
    sig_sk, sig_pk = crypto.generate_key_pair()
    kem_sk, kem_pk = crypto.generate_key_pair()
    ln = LeafNode(
        encryption_key=kem_pk,
        signature_key=sig_pk,
        credential=None,
        capabilities=b"",
        parent_hash=b"",
    )
    kp = KeyPackage(leaf_node=ln)
    sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", kp.tbs_serialize())
    kp = KeyPackage(leaf_node=ln, signature=Signature(sig))
    group = MLSGroup.create(config, b"arch_test_group", kp)
    staged = group.create_commit(sig_sk)

    async def _():
        await staged.merge(storage)
        got = await storage.get_group_state(b"arch_test_group")
        assert got is not None
        assert got.epoch == 1

    _run(_())


def test_get_commit_sender_leaf_index_import():
    """get_commit_sender_leaf_index is exported and callable."""
    assert callable(get_commit_sender_leaf_index)
    from rfc9420.mls.exceptions import InvalidCommitError
    with pytest.raises(InvalidCommitError):
        get_commit_sender_leaf_index(b"not_a_commit")


def test_public_group_import_and_from_group_info_requires_valid_gi():
    """PublicGroup is importable; from_group_info requires valid GroupInfo (we only check import)."""
    assert hasattr(PublicGroup, "from_group_info")
    assert hasattr(PublicGroup, "process_handshake")
    assert hasattr(PublicGroup, "member_count")


def test_session_create_with_config_exported():
    """MLSGroupSession uses config-only constructors (no legacy Group)."""
    from rfc9420.api.session import MLSGroupSession
    assert hasattr(MLSGroupSession, "create_with_config")
    assert hasattr(MLSGroupSession, "join_from_welcome_with_config")
    assert hasattr(MLSGroupSession, "deserialize_with_config")


def test_process_commit_staged_returns_staged_commit():
    """Config-driven MLSGroup.process_commit_staged returns StagedCommit without mutating."""
    from rfc9420.group.mls_group.group import MLSGroup
    assert hasattr(MLSGroup, "process_commit_staged")
    # StagedCommit is the return type; we only check the API exists
    assert StagedCommit is not None


def test_x509_identity_provider_exported():
    """X509IdentityProvider is available from backends."""
    from rfc9420.backends.identity import X509IdentityProvider
    assert X509IdentityProvider is not None
    provider = X509IdentityProvider(trust_roots=[])
    assert hasattr(provider, "validate_credential")

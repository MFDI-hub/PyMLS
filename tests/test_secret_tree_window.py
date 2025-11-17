import os
from collections import OrderedDict

from pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from pymls.protocol.secret_tree import SecretTree


def _derive_reference_app(crypto, encryption_secret: bytes, leaf: int, generation: int):
    """Reference derivation matching legacy on-demand path (no cache)."""
    st = SecretTree(encryption_secret, crypto, n_leaves=1, window_size=0)
    # Access internal helpers for exact parity
    leaf_secret = st._derive_leaf_secret(encryption_secret, leaf)  # type: ignore[attr-defined]
    secret = crypto.derive_secret(leaf_secret, b"application")
    key = nonce = b""
    for _ in range(generation + 1):
        key, nonce, secret = st._ratchet_step(secret)  # type: ignore[attr-defined]
    return key, nonce


def test_secret_tree_window_out_of_order_and_eviction():
    crypto = DefaultCryptoProvider()
    Nh = crypto.kdf_hash_len()
    encryption_secret = os.urandom(Nh)

    # Use a small window for eviction behavior
    st = SecretTree(encryption_secret, crypto, n_leaves=1, window_size=3)

    # Receive generation 3 first -> cache gens 0,1,2; return gen 3
    k3, n3, g3 = st.application_for(0, 3)
    assert g3 == 3

    # Now fetch generation 1 -> should come from skipped cache and match reference
    k1_ref, n1_ref = _derive_reference_app(crypto, encryption_secret, 0, 1)
    k1, n1, g1 = st.application_for(0, 1)
    assert g1 == 1
    assert k1 == k1_ref and n1 == n1_ref

    # Push beyond window: request generation 7 -> caches 4,5,6 (evicts oldest)
    k7, n7, g7 = st.application_for(0, 7)
    assert g7 == 7

    # Internal check: oldest cached generations should have been evicted
    st_leaf = st._leaves[0]  # type: ignore[attr-defined]
    assert isinstance(st_leaf.app_skipped, OrderedDict)
    assert len(st_leaf.app_skipped) <= 3
    # Generation 1 should no longer be cached
    assert 1 not in st_leaf.app_skipped


def _derive_reference_hs(crypto, encryption_secret: bytes, leaf: int, generation: int):
    st = SecretTree(encryption_secret, crypto, n_leaves=1, window_size=0)
    leaf_secret = st._derive_leaf_secret(encryption_secret, leaf)  # type: ignore[attr-defined]
    secret = crypto.derive_secret(leaf_secret, b"handshake")
    key = nonce = b""
    for _ in range(generation + 1):
        key, nonce, secret = st._ratchet_step(secret)  # type: ignore[attr-defined]
    return key, nonce


def test_secret_tree_window_handshake_branch():
    crypto = DefaultCryptoProvider()
    Nh = crypto.kdf_hash_len()
    encryption_secret = os.urandom(Nh)

    st = SecretTree(encryption_secret, crypto, n_leaves=1, window_size=2)

    # Receive generation 2 first -> caches gens 0,1
    kh2, nh2, gh2 = st.handshake_for(0, 2)
    assert gh2 == 2

    # Later receive generation 0 from cache
    k0_ref, n0_ref = _derive_reference_hs(crypto, encryption_secret, 0, 0)
    k0, n0, g0 = st.handshake_for(0, 0)
    assert g0 == 0
    assert k0 == k0_ref and n0 == n0_ref



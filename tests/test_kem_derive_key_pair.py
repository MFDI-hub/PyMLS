import pytest

from pymls.crypto.default_crypto_provider import DefaultCryptoProvider


def test_derive_key_pair_is_deterministic():
    crypto = DefaultCryptoProvider()
    seed = b"deterministic-seed-for-ikm-" * 2
    sk1, pk1 = crypto.derive_key_pair(seed)
    sk2, pk2 = crypto.derive_key_pair(seed)
    assert sk1 == sk2
    assert pk1 == pk2



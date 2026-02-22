import unittest

from tests.helpers import has_hpke

from rfc9420 import DefaultCryptoProvider
from rfc9420.crypto.hpke_labels import (
    decrypt_with_label,
    encode_encrypt_context,
    encrypt_with_label,
)


class TestUnitHPKELabels(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_context_contains_mls_prefix(self):
        ctx = encode_encrypt_context(b"Welcome", b"group-ctx")
        self.assertIn(b"MLS 1.0 Welcome", ctx)

    def test_encrypt_decrypt_roundtrip(self):
        sk, pk = self.crypto.generate_key_pair()
        enc, ct = encrypt_with_label(
            self.crypto,
            pk,
            b"Welcome",
            b"context",
            b"aad",
            b"secret",
        )
        out = decrypt_with_label(
            self.crypto,
            sk,
            enc,
            b"Welcome",
            b"context",
            b"aad",
            ct,
        )
        self.assertEqual(out, b"secret")


if __name__ == "__main__":
    unittest.main()

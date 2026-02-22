import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rfc9420 import DefaultCryptoProvider
from rfc9420.mls.exceptions import InvalidSignatureError, UnsupportedCipherSuiteError


class TestUnitCryptoProvider(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_supported_and_active_suite(self):
        self.assertIn(0x0001, self.crypto.supported_ciphersuites)
        self.assertEqual(self.crypto.active_ciphersuite.suite_id, 0x0001)

    def test_set_invalid_suite(self):
        with self.assertRaises(UnsupportedCipherSuiteError):
            self.crypto.set_ciphersuite(0x9999)

    def test_aead_roundtrip(self):
        key = b"\x11" * self.crypto.aead_key_size()
        nonce = b"\x22" * self.crypto.aead_nonce_size()
        ct = self.crypto.aead_encrypt(key, nonce, b"msg", b"aad")
        self.assertEqual(self.crypto.aead_decrypt(key, nonce, ct, b"aad"), b"msg")
        with self.assertRaises(InvalidTag):
            self.crypto.aead_decrypt(key, nonce, ct, b"bad")

    def test_sign_verify(self):
        sk = Ed25519PrivateKey.generate()
        sk_b = sk.private_bytes_raw()
        pk_b = sk.public_key().public_bytes_raw()
        sig = self.crypto.sign(sk_b, b"payload")
        self.crypto.verify(pk_b, b"payload", sig)
        with self.assertRaises(InvalidSignatureError):
            self.crypto.verify(pk_b, b"payload", b"\x00" * len(sig))

    def test_derive_key_pair_is_deterministic(self):
        sk1, pk1 = self.crypto.derive_key_pair(b"s" * 32)
        sk2, pk2 = self.crypto.derive_key_pair(b"s" * 32)
        self.assertEqual(sk1, sk2)
        self.assertEqual(pk1, pk2)


if __name__ == "__main__":
    unittest.main()

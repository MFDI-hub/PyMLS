import unittest
from src.pymls import DefaultCryptoProvider


class TestCryptoProvider(unittest.TestCase):
    def test_labeled_expand_and_derive(self):
        c = DefaultCryptoProvider()
        prk = c.kdf_extract(b"salt", b"ikm")
        out1 = c.expand_with_label(prk, b"label", b"context", 16)
        out2 = c.expand_with_label(prk, b"label", b"context", 16)
        self.assertEqual(out1, out2)
        ds = c.derive_secret(prk, b"label2")
        self.assertEqual(len(ds), c.kdf_hash_len())

    def test_aead_roundtrip(self):
        c = DefaultCryptoProvider()
        key = b"\x01" * c.aead_key_size()
        nonce = b"\x02" * c.aead_nonce_size()
        pt = b"hello"
        ct = c.aead_encrypt(key, nonce, pt, b"aad")
        out = c.aead_decrypt(key, nonce, ct, b"aad")
        self.assertEqual(out, pt)

    def test_hmac_sign_verify(self):
        c = DefaultCryptoProvider()
        tag = c.hmac_sign(b"k", b"d")
        c.hmac_verify(b"k", b"d", tag)
        with self.assertRaises(Exception):
            c.hmac_verify(b"k", b"d", b"\x00" * len(tag))

    def test_hpke_roundtrip(self):
        c = DefaultCryptoProvider()
        sk, pk = c.generate_key_pair()
        enc, ct = c.hpke_seal(pk, b"info", b"aad", b"pt")
        out = c.hpke_open(sk, enc, b"info", b"aad", ct)
        self.assertEqual(out, b"pt")


if __name__ == "__main__":
    unittest.main()



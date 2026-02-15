"""Comprehensive tests for rfc9420.crypto.hpke_labels module."""

import unittest

from rfc9420.crypto.hpke_labels import (
    encode_encrypt_context,
    encrypt_with_label,
    decrypt_with_label,
)
from rfc9420 import DefaultCryptoProvider
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


try:
    import cryptography.hazmat.primitives.hpke  # noqa: F401

    _HAS_HPKE = True
except Exception:
    _HAS_HPKE = False


class TestHPKELabels(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        if not _HAS_HPKE:
            self.skipTest("HPKE support not available in this cryptography build")

    def test_encode_encrypt_context_empty(self):
        """Test encoding EncryptContext with empty label and context."""
        result = encode_encrypt_context(b"", b"")
        # Should have 4-byte length prefix for label + 4-byte length prefix for context
        # Label should be "MLS 1.0 " (8 bytes) + empty
        self.assertGreater(len(result), 0)

    def test_encode_encrypt_context_with_data(self):
        """Test encoding EncryptContext with label and context."""
        label = b"test_label"
        context = b"test_context"
        result = encode_encrypt_context(label, context)

        # Should contain the label prefixed with "MLS 1.0 "
        self.assertIn(b"MLS 1.0 test_label", result)
        self.assertIn(context, result)

    def test_encode_encrypt_context_roundtrip_structure(self):
        """Test that encode_encrypt_context produces valid structure."""
        label = b"Welcome"
        context = b"group_context"
        result = encode_encrypt_context(label, context)

        # Should have length prefixes
        self.assertGreater(len(result), len(label) + len(context) + 8)  # +8 for "MLS 1.0 "

    def test_encrypt_decrypt_with_label_roundtrip(self):
        """Test encrypt_with_label and decrypt_with_label roundtrip."""
        # Generate key pair
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes_raw()
        pk_bytes = pk.public_bytes_raw()

        label = b"Welcome"
        context = b"group_context"
        aad = b"additional_data"
        plaintext = b"secret_message"

        # Encrypt
        enc, ciphertext = encrypt_with_label(
            self.crypto,
            pk_bytes,
            label,
            context,
            aad,
            plaintext,
        )

        self.assertIsInstance(enc, bytes)
        self.assertIsInstance(ciphertext, bytes)
        self.assertGreater(len(enc), 0)
        self.assertGreater(len(ciphertext), 0)

        # Decrypt
        decrypted = decrypt_with_label(
            self.crypto,
            sk_bytes,
            enc,
            label,
            context,
            aad,
            ciphertext,
        )

        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_with_label_different_contexts(self):
        """Test that different contexts produce different ciphertexts."""
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes_raw()
        pk_bytes = pk.public_bytes_raw()

        label = b"Welcome"
        plaintext = b"secret"
        aad = b""

        # Encrypt with context1
        enc1, ct1 = encrypt_with_label(
            self.crypto,
            pk_bytes,
            label,
            b"context1",
            aad,
            plaintext,
        )

        # Encrypt with context2
        enc2, ct2 = encrypt_with_label(
            self.crypto,
            pk_bytes,
            label,
            b"context2",
            aad,
            plaintext,
        )

        # Should produce different ciphertexts
        self.assertNotEqual(ct1, ct2)

        # But both should decrypt correctly
        dec1 = decrypt_with_label(self.crypto, sk_bytes, enc1, label, b"context1", aad, ct1)
        dec2 = decrypt_with_label(self.crypto, sk_bytes, enc2, label, b"context2", aad, ct2)

        self.assertEqual(dec1, plaintext)
        self.assertEqual(dec2, plaintext)

    def test_encrypt_decrypt_with_label_different_labels(self):
        """Test that different labels produce different ciphertexts."""
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        pk_bytes = pk.public_bytes_raw()

        context = b"context"
        plaintext = b"secret"
        aad = b""

        # Encrypt with label1
        enc1, ct1 = encrypt_with_label(
            self.crypto,
            pk_bytes,
            b"label1",
            context,
            aad,
            plaintext,
        )

        # Encrypt with label2
        enc2, ct2 = encrypt_with_label(
            self.crypto,
            pk_bytes,
            b"label2",
            context,
            aad,
            plaintext,
        )

        # Should produce different ciphertexts
        self.assertNotEqual(ct1, ct2)

    def test_encrypt_decrypt_with_label_empty_plaintext(self):
        """Test encrypt/decrypt with empty plaintext."""
        sk = X25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes_raw()
        pk_bytes = pk.public_bytes_raw()

        enc, ct = encrypt_with_label(
            self.crypto,
            pk_bytes,
            b"label",
            b"context",
            b"aad",
            b"",
        )

        decrypted = decrypt_with_label(
            self.crypto,
            sk_bytes,
            enc,
            b"label",
            b"context",
            b"aad",
            ct,
        )

        self.assertEqual(decrypted, b"")


if __name__ == "__main__":
    unittest.main()

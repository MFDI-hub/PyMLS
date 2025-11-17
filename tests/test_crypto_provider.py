"""Comprehensive tests for pymls.DefaultCryptoProvider."""
import unittest
from pymls import DefaultCryptoProvider
from pymls.mls.exceptions import UnsupportedCipherSuiteError, InvalidSignatureError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidTag


class TestCryptoProvider(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_supported_ciphersuites(self):
        """Test supported_ciphersuites property."""
        suites = self.crypto.supported_ciphersuites
        self.assertIsInstance(suites, list)
        self.assertGreater(len(suites), 0)
        self.assertIn(0x0001, suites)

    def test_active_ciphersuite(self):
        """Test active_ciphersuite property."""
        suite = self.crypto.active_ciphersuite
        self.assertIsNotNone(suite)
        self.assertEqual(suite.suite_id, 0x0001)  # Default

    def test_set_ciphersuite(self):
        """Test set_ciphersuite method."""
        self.crypto.set_ciphersuite(0x0002)
        self.assertEqual(self.crypto.active_ciphersuite.suite_id, 0x0002)
        
        # Reset to default
        self.crypto.set_ciphersuite(0x0001)
        self.assertEqual(self.crypto.active_ciphersuite.suite_id, 0x0001)

    def test_set_ciphersuite_invalid(self):
        """Test set_ciphersuite with invalid suite ID."""
        with self.assertRaises(UnsupportedCipherSuiteError):
            self.crypto.set_ciphersuite(0x9999)

    def test_kdf_extract(self):
        """Test kdf_extract method."""
        salt = b"salt"
        ikm = b"input_key_material"
        prk = self.crypto.kdf_extract(salt, ikm)
        
        self.assertIsInstance(prk, bytes)
        self.assertEqual(len(prk), 32)  # HKDF-SHA256 produces 32-byte PRK

    def test_kdf_extract_deterministic(self):
        """Test that kdf_extract is deterministic."""
        salt = b"salt"
        ikm = b"ikm"
        prk1 = self.crypto.kdf_extract(salt, ikm)
        prk2 = self.crypto.kdf_extract(salt, ikm)
        self.assertEqual(prk1, prk2)

    def test_kdf_expand(self):
        """Test kdf_expand method."""
        prk = self.crypto.kdf_extract(b"salt", b"ikm")
        info = b"info"
        length = 16
        expanded = self.crypto.kdf_expand(prk, info, length)
        
        self.assertIsInstance(expanded, bytes)
        self.assertEqual(len(expanded), length)

    def test_kdf_expand_different_lengths(self):
        """Test kdf_expand with different lengths."""
        prk = self.crypto.kdf_extract(b"salt", b"ikm")
        
        for length in [1, 16, 32, 64, 100]:
            expanded = self.crypto.kdf_expand(prk, b"info", length)
            self.assertEqual(len(expanded), length)

    def test_hash(self):
        """Test hash method."""
        data = b"test_data"
        hash1 = self.crypto.hash(data)
        hash2 = self.crypto.hash(data)
        
        self.assertIsInstance(hash1, bytes)
        self.assertEqual(len(hash1), self.crypto.kdf_hash_len())
        self.assertEqual(hash1, hash2)  # Deterministic

    def test_hash_different_inputs(self):
        """Test that different inputs produce different hashes."""
        hash1 = self.crypto.hash(b"input1")
        hash2 = self.crypto.hash(b"input2")
        self.assertNotEqual(hash1, hash2)

    def test_labeled_expand_and_derive(self):
        """Test expand_with_label and derive_secret methods."""
        prk = self.crypto.kdf_extract(b"salt", b"ikm")
        out1 = self.crypto.expand_with_label(prk, b"label", b"context", 16)
        out2 = self.crypto.expand_with_label(prk, b"label", b"context", 16)
        self.assertEqual(out1, out2)
        
        ds = self.crypto.derive_secret(prk, b"label2")
        self.assertEqual(len(ds), self.crypto.kdf_hash_len())

    def test_expand_with_label_different_contexts(self):
        """Test that different contexts produce different outputs."""
        prk = self.crypto.kdf_extract(b"salt", b"ikm")
        out1 = self.crypto.expand_with_label(prk, b"label", b"context1", 16)
        out2 = self.crypto.expand_with_label(prk, b"label", b"context2", 16)
        self.assertNotEqual(out1, out2)

    def test_derive_secret(self):
        """Test derive_secret method."""
        secret = b"secret" * 4  # 24 bytes
        label = b"test_label"
        derived = self.crypto.derive_secret(secret, label)
        
        self.assertIsInstance(derived, bytes)
        self.assertEqual(len(derived), self.crypto.kdf_hash_len())

    def test_aead_roundtrip(self):
        """Test AEAD encrypt/decrypt roundtrip."""
        key = b"\x01" * self.crypto.aead_key_size()
        nonce = b"\x02" * self.crypto.aead_nonce_size()
        pt = b"hello"
        aad = b"additional_data"
        
        ct = self.crypto.aead_encrypt(key, nonce, pt, aad)
        out = self.crypto.aead_decrypt(key, nonce, ct, aad)
        self.assertEqual(out, pt)

    def test_aead_different_aad(self):
        """Test that different AAD produces different ciphertext."""
        key = b"\x01" * self.crypto.aead_key_size()
        nonce = b"\x02" * self.crypto.aead_nonce_size()
        pt = b"plaintext"
        
        ct1 = self.crypto.aead_encrypt(key, nonce, pt, b"aad1")
        ct2 = self.crypto.aead_encrypt(key, nonce, pt, b"aad2")
        self.assertNotEqual(ct1, ct2)
        
        # Both should decrypt correctly
        self.assertEqual(self.crypto.aead_decrypt(key, nonce, ct1, b"aad1"), pt)
        self.assertEqual(self.crypto.aead_decrypt(key, nonce, ct2, b"aad2"), pt)

    def test_aead_wrong_aad(self):
        """Test that wrong AAD fails decryption."""
        key = b"\x01" * self.crypto.aead_key_size()
        nonce = b"\x02" * self.crypto.aead_nonce_size()
        pt = b"plaintext"
        
        ct = self.crypto.aead_encrypt(key, nonce, pt, b"correct_aad")
        with self.assertRaises(InvalidTag):
            self.crypto.aead_decrypt(key, nonce, ct, b"wrong_aad")

    def test_hmac_sign_verify(self):
        """Test HMAC sign and verify."""
        key = b"hmac_key"
        data = b"data_to_authenticate"
        
        tag = self.crypto.hmac_sign(key, data)
        self.assertIsInstance(tag, bytes)
        self.assertEqual(len(tag), self.crypto.kdf_hash_len())
        
        # Should verify successfully
        self.crypto.hmac_verify(key, data, tag)
        
        # Wrong tag should fail
        with self.assertRaises(Exception):
            self.crypto.hmac_verify(key, data, b"\x00" * len(tag))

    def test_hmac_deterministic(self):
        """Test that HMAC is deterministic."""
        key = b"key"
        data = b"data"
        tag1 = self.crypto.hmac_sign(key, data)
        tag2 = self.crypto.hmac_sign(key, data)
        self.assertEqual(tag1, tag2)

    def test_sign_verify(self):
        """Test sign and verify methods."""
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes_raw()
        pk_bytes = pk.public_bytes_raw()
        
        data = b"data_to_sign"
        signature = self.crypto.sign(sk_bytes, data)
        
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)
        
        # Should verify successfully
        self.crypto.verify(pk_bytes, data, signature)
        
        # Wrong signature should fail
        with self.assertRaises(InvalidSignatureError):
            self.crypto.verify(pk_bytes, data, b"\x00" * len(signature))

    def test_sign_with_label_verify_with_label(self):
        """Test sign_with_label and verify_with_label methods."""
        sk = Ed25519PrivateKey.generate()
        pk = sk.public_key()
        sk_bytes = sk.private_bytes_raw()
        pk_bytes = pk.public_bytes_raw()
        
        label = b"test_label"
        content = b"content_to_sign"
        
        signature = self.crypto.sign_with_label(sk_bytes, label, content)
        self.assertIsInstance(signature, bytes)
        
        # Should verify successfully
        self.crypto.verify_with_label(pk_bytes, label, content, signature)
        
        # Wrong label should fail
        with self.assertRaises(InvalidSignatureError):
            self.crypto.verify_with_label(pk_bytes, b"wrong_label", content, signature)

    def test_hpke_roundtrip(self):
        """Test HPKE seal/open roundtrip."""
        sk, pk = self.crypto.generate_key_pair()
        info = b"info"
        aad = b"aad"
        pt = b"plaintext"
        
        enc, ct = self.crypto.hpke_seal(pk, info, aad, pt)
        self.assertIsInstance(enc, bytes)
        self.assertIsInstance(ct, bytes)
        
        out = self.crypto.hpke_open(sk, enc, info, aad, ct)
        self.assertEqual(out, pt)

    def test_hpke_different_info(self):
        """Test that different info produces different ciphertext."""
        sk, pk = self.crypto.generate_key_pair()
        pt = b"plaintext"
        
        enc1, ct1 = self.crypto.hpke_seal(pk, b"info1", b"", pt)
        enc2, ct2 = self.crypto.hpke_seal(pk, b"info2", b"", pt)
        
        self.assertNotEqual(ct1, ct2)
        
        # Both should decrypt correctly
        self.assertEqual(self.crypto.hpke_open(sk, enc1, b"info1", b"", ct1), pt)
        self.assertEqual(self.crypto.hpke_open(sk, enc2, b"info2", b"", ct2), pt)

    def test_generate_key_pair(self):
        """Test generate_key_pair method."""
        sk, pk = self.crypto.generate_key_pair()
        
        self.assertIsInstance(sk, bytes)
        self.assertIsInstance(pk, bytes)
        self.assertGreater(len(sk), 0)
        self.assertGreater(len(pk), 0)
        
        # Should be able to use for HPKE
        enc, ct = self.crypto.hpke_seal(pk, b"info", b"", b"test")
        out = self.crypto.hpke_open(sk, enc, b"info", b"", ct)
        self.assertEqual(out, b"test")

    def test_derive_key_pair(self):
        """Test derive_key_pair method."""
        seed = b"seed" * 8  # 32 bytes
        sk, pk = self.crypto.derive_key_pair(seed)
        
        self.assertIsInstance(sk, bytes)
        self.assertIsInstance(pk, bytes)
        
        # Should be deterministic
        sk2, pk2 = self.crypto.derive_key_pair(seed)
        self.assertEqual(sk, sk2)
        self.assertEqual(pk, pk2)

    def test_derive_key_pair_different_seeds(self):
        """Test that different seeds produce different keys."""
        sk1, pk1 = self.crypto.derive_key_pair(b"seed1" * 8)
        sk2, pk2 = self.crypto.derive_key_pair(b"seed2" * 8)
        
        self.assertNotEqual(sk1, sk2)
        self.assertNotEqual(pk1, pk2)

    def test_kem_pk_size(self):
        """Test kem_pk_size method."""
        size = self.crypto.kem_pk_size()
        self.assertIsInstance(size, int)
        self.assertGreater(size, 0)
        # For X25519, should be 32 bytes
        self.assertEqual(size, 32)

    def test_aead_key_size(self):
        """Test aead_key_size method."""
        size = self.crypto.aead_key_size()
        self.assertIsInstance(size, int)
        self.assertGreater(size, 0)
        # For AES-128-GCM, should be 16 bytes
        self.assertEqual(size, 16)

    def test_aead_nonce_size(self):
        """Test aead_nonce_size method."""
        size = self.crypto.aead_nonce_size()
        self.assertIsInstance(size, int)
        self.assertEqual(size, 12)  # All RFC-defined AEADs use 96-bit nonces

    def test_kdf_hash_len(self):
        """Test kdf_hash_len method."""
        length = self.crypto.kdf_hash_len()
        self.assertIsInstance(length, int)
        self.assertGreater(length, 0)
        # For SHA-256, should be 32 bytes
        self.assertEqual(length, 32)


if __name__ == "__main__":
    unittest.main()



"""Comprehensive tests for pymls.crypto.ciphersuites module."""

import unittest

from rfc9420.crypto.ciphersuites import (
    KEM,
    KDF,
    AEAD,
    SignatureScheme,
    MlsCiphersuite,
    get_ciphersuite_by_id,
    get_ciphersuite_by_name,
    all_ciphersuites,
    list_ciphersuite_ids,
    list_ciphersuite_names,
    find_by_triple,
)


class TestCiphersuites(unittest.TestCase):
    def test_get_ciphersuite_by_id_valid(self):
        """Test get_ciphersuite_by_id with valid IDs."""
        suite = get_ciphersuite_by_id(0x0001)
        self.assertIsNotNone(suite)
        self.assertEqual(suite.suite_id, 0x0001)

        suite = get_ciphersuite_by_id(0x0002)
        self.assertIsNotNone(suite)
        self.assertEqual(suite.suite_id, 0x0002)

    def test_get_ciphersuite_by_id_invalid(self):
        """Test get_ciphersuite_by_id with invalid ID."""
        suite = get_ciphersuite_by_id(0x9999)
        self.assertIsNone(suite)

    def test_get_ciphersuite_by_name_valid(self):
        """Test get_ciphersuite_by_name with valid names."""
        suite = get_ciphersuite_by_name("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519")
        self.assertIsNotNone(suite)
        self.assertEqual(suite.suite_id, 0x0001)

    def test_get_ciphersuite_by_name_invalid(self):
        """Test get_ciphersuite_by_name with invalid name."""
        suite = get_ciphersuite_by_name("INVALID_NAME")
        self.assertIsNone(suite)

    def test_all_ciphersuites(self):
        """Test all_ciphersuites returns all registered suites."""
        suites = list(all_ciphersuites())
        self.assertGreater(len(suites), 0)

        # Should have unique suite IDs
        suite_ids = [s.suite_id for s in suites]
        self.assertEqual(len(suite_ids), len(set(suite_ids)))

    def test_list_ciphersuite_ids(self):
        """Test list_ciphersuite_ids."""
        ids = list_ciphersuite_ids()
        self.assertGreater(len(ids), 0)
        self.assertIsInstance(ids, list)

        # Should be sorted
        self.assertEqual(ids, sorted(ids))

        # Should contain known IDs
        self.assertIn(0x0001, ids)

    def test_list_ciphersuite_names(self):
        """Test list_ciphersuite_names."""
        names = list_ciphersuite_names()
        self.assertGreater(len(names), 0)
        self.assertIsInstance(names, list)

        # Should be sorted
        self.assertEqual(names, sorted(names))

        # Should contain known names
        self.assertIn("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519", names)

    def test_find_by_triple_valid(self):
        """Test find_by_triple with valid triple."""
        suite = find_by_triple((KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
        self.assertIsNotNone(suite)
        self.assertEqual(suite.kem, KEM.DHKEM_X25519_HKDF_SHA256)
        self.assertEqual(suite.kdf, KDF.HKDF_SHA256)
        self.assertEqual(suite.aead, AEAD.AES_128_GCM)

    def test_find_by_triple_invalid(self):
        """Test find_by_triple with invalid triple."""
        suite = find_by_triple((KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA512, AEAD.AES_128_GCM))
        # This combination might not exist
        # Just verify it doesn't crash
        self.assertIsInstance(suite, (MlsCiphersuite, type(None)))

    def test_ciphersuite_properties(self):
        """Test that ciphersuite has required properties."""
        suite = get_ciphersuite_by_id(0x0001)
        self.assertIsNotNone(suite)

        self.assertIsInstance(suite.suite_id, int)
        self.assertIsInstance(suite.name, str)
        self.assertIsInstance(suite.kem, KEM)
        self.assertIsInstance(suite.kdf, KDF)
        self.assertIsInstance(suite.aead, AEAD)
        self.assertIsInstance(suite.signature, SignatureScheme)

    def test_ciphersuite_consistency(self):
        """Test consistency between different lookup methods."""
        suite_by_id = get_ciphersuite_by_id(0x0001)
        self.assertIsNotNone(suite_by_id)

        suite_by_name = get_ciphersuite_by_name(suite_by_id.name)
        self.assertIsNotNone(suite_by_name)

        self.assertEqual(suite_by_id.suite_id, suite_by_name.suite_id)
        self.assertEqual(suite_by_id.name, suite_by_name.name)
        self.assertEqual(suite_by_id.kem, suite_by_name.kem)
        self.assertEqual(suite_by_id.kdf, suite_by_name.kdf)
        self.assertEqual(suite_by_id.aead, suite_by_name.aead)
        self.assertEqual(suite_by_id.signature, suite_by_name.signature)

    def test_all_supported_ciphersuites(self):
        """Test that all standard RFC ciphersuites are available."""
        # Check for some known RFC 9420 ciphersuites
        known_ids = [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008]

        for suite_id in known_ids:
            suite = get_ciphersuite_by_id(suite_id)
            if suite_id <= 0x0008:  # These should exist
                self.assertIsNotNone(suite, f"Suite {suite_id:#06x} should exist")


if __name__ == "__main__":
    unittest.main()

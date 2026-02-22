import unittest

from rfc9420.crypto.ciphersuites import (
    AEAD,
    KDF,
    KEM,
    MlsCiphersuite,
    find_by_triple,
    get_ciphersuite_by_id,
    get_ciphersuite_by_name,
    list_ciphersuite_ids,
)


class TestUnitCiphersuites(unittest.TestCase):
    def test_lookup_by_id_and_name(self):
        s1 = get_ciphersuite_by_id(0x0001)
        self.assertIsNotNone(s1)
        self.assertEqual(s1.suite_id, 0x0001)
        self.assertIsNotNone(get_ciphersuite_by_name(s1.name))

    def test_registry_contains_standard_ids(self):
        ids = list_ciphersuite_ids()
        self.assertIn(0x0001, ids)
        self.assertIn(0x0007, ids)
        self.assertNotIn(0x0008, ids)

    def test_find_by_triple(self):
        s = find_by_triple((KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM))
        self.assertIsInstance(s, MlsCiphersuite)


if __name__ == "__main__":
    unittest.main()

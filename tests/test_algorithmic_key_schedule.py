import unittest

from rfc9420 import DefaultCryptoProvider
from rfc9420.protocol.data_structures import GroupContext
from rfc9420.protocol.key_schedule import KeySchedule


class TestAlgorithmicKeySchedule(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        self.gc = GroupContext(b"gid", 1, b"tree-hash", b"confirmed-th")

    def test_export_is_deterministic(self):
        ks = KeySchedule(b"init", b"commit", self.gc, None, self.crypto)
        a = ks.export(b"LABEL", b"CTX", 24)
        b = ks.export(b"LABEL", b"CTX", 24)
        self.assertEqual(a, b)

    def test_sender_nonce_depends_on_reuse_guard(self):
        ks = KeySchedule(b"init", b"commit", self.gc, None, self.crypto)
        n1 = ks.sender_data_nonce(b"\x00\x00\x00\x01")
        n2 = ks.sender_data_nonce(b"\x00\x00\x00\x02")
        self.assertNotEqual(n1, n2)

    def test_from_epoch_secret_consistency(self):
        ks1 = KeySchedule.from_epoch_secret(b"E" * self.crypto.kdf_hash_len(), self.gc, self.crypto)
        ks2 = KeySchedule.from_epoch_secret(b"E" * self.crypto.kdf_hash_len(), self.gc, self.crypto)
        self.assertEqual(ks1.exporter_secret, ks2.exporter_secret)


if __name__ == "__main__":
    unittest.main()

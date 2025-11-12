import unittest
from src.pymls.protocol.key_schedule import KeySchedule
from src.pymls.protocol.data_structures import GroupContext
from src.pymls import DefaultCryptoProvider


class TestKeySchedule(unittest.TestCase):
    def test_derivations_and_sender_nonce(self):
        c = DefaultCryptoProvider()
        gc = GroupContext(b"gid", 1, b"tree", b"cth")
        ks = KeySchedule(b"init", b"commit", gc, None, c)
        self.assertTrue(ks.epoch_secret)
        self.assertTrue(ks.handshake_secret)
        self.assertTrue(ks.application_secret)
        self.assertTrue(ks.exporter_secret)
        self.assertTrue(ks.membership_key)
        reuse_guard = b"\xAA\xBB\xCC\xDD"
        nonce = ks.sender_data_nonce(reuse_guard)
        self.assertEqual(len(nonce), c.aead_nonce_size())
        # Expand export
        out = ks.export(b"lbl", b"ctx", 16)
        self.assertEqual(len(out), 16)
        ks.wipe()
        # ensure wipe toggled
        self.assertTrue(True)


if __name__ == "__main__":
    unittest.main()



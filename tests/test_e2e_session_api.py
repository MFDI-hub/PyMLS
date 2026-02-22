import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider
from rfc9420.api import MLSGroupSession


class TestE2ESessionAPI(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_session_flow(self):
        alice = make_member(b"alice", self.crypto)
        bob = make_member(b"bob", self.crypto)

        a = MLSGroupSession.create(b"sess-group", alice.key_package, self.crypto)
        proposal_bytes = a.add_member(bob.key_package, alice.signing_private_key)
        a.process_proposal(proposal_bytes, sender_leaf_index=0)
        commit_bytes, welcomes = a.commit(alice.signing_private_key)
        self.assertGreaterEqual(len(welcomes), 1)

        b = MLSGroupSession.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        b.apply_commit(commit_bytes, sender_leaf_index=0)
        self.assertEqual(a.group_id, b.group_id)
        self.assertEqual(a.epoch, b.epoch)

        msg = a.protect_application(b"session-msg")
        sender, plain = b.unprotect_application(msg)
        self.assertEqual(sender, 0)
        self.assertEqual(plain, b"session-msg")

        k1 = a.export_secret(b"APP_MEDIA_KEY", b"ctx", 32)
        k2 = b.export_secret(b"APP_MEDIA_KEY", b"ctx", 32)
        self.assertEqual(k1, k2)


if __name__ == "__main__":
    unittest.main()

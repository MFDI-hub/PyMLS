import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group


class TestE2EGroupLifecycle(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_create_add_join_and_message(self):
        alice = make_member(b"alice", self.crypto)
        bob = make_member(b"bob", self.crypto)

        group_a = Group.create(b"group-e2e", alice.key_package, self.crypto)
        proposal = group_a.add(bob.key_package, alice.signing_private_key)
        group_a.process_proposal(proposal, sender_leaf_index=0)
        commit, welcomes = group_a.commit(alice.signing_private_key)
        self.assertGreaterEqual(len(welcomes), 1)

        group_b = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        group_b.apply_commit(commit, sender_leaf_index=0)
        self.assertEqual(group_a.epoch, group_b.epoch)

        ct = group_a.protect(b"hello-bob")
        sender, pt = group_b.unprotect(ct)
        self.assertEqual(sender, 0)
        self.assertEqual(pt, b"hello-bob")


if __name__ == "__main__":
    unittest.main()

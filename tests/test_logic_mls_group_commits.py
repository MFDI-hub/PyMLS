import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group


class TestLogicMLSGroupCommits(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_add_commit_increments_epoch(self):
        a = make_member(b"a", self.crypto)
        b = make_member(b"b", self.crypto)
        group = Group.create(b"gid", a.key_package, self.crypto)
        p = group.add(b.key_package, a.signing_private_key)
        group.process_proposal(p, 0)
        _, welcomes = group.commit(a.signing_private_key)
        self.assertGreaterEqual(len(welcomes), 1)
        self.assertEqual(group.epoch, 1)

    def test_apply_invalid_sender_index_raises(self):
        a = make_member(b"a", self.crypto)
        group = Group.create(b"gid2", a.key_package, self.crypto)
        commit, _ = group.commit(a.signing_private_key)
        with self.assertRaises(Exception):
            group.apply_commit(commit, sender_leaf_index=7)


if __name__ == "__main__":
    unittest.main()

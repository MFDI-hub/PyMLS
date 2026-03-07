import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import (
    DefaultCryptoProvider,
    Group,
    get_commit_sender_leaf_index,
    InvalidCommitError,
    SenderType,
)


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
        with self.assertRaises(InvalidCommitError):
            group.apply_commit(commit, sender_leaf_index=7)

    def test_apply_commit_without_sender_extracts_from_message(self):
        a = make_member(b"a", self.crypto)
        b = make_member(b"b", self.crypto)
        group_a = Group.create(b"gid3", a.key_package, self.crypto)
        group_a.process_proposal(group_a.add(b.key_package, a.signing_private_key), 0, SenderType.MEMBER)
        commit, welcomes = group_a.commit(a.signing_private_key)
        self.assertEqual(get_commit_sender_leaf_index(commit.serialize()), 0)
        group_b = Group.join_from_welcome(welcomes[0], b.hpke_private_key, self.crypto)
        group_b.apply_commit(commit)  # no sender_leaf_index
        self.assertEqual(group_a.epoch, group_b.epoch)

    def test_iter_members_returns_leaf_index_and_identity(self):
        a = make_member(b"alice-id", self.crypto)
        group = Group.create(b"gid4", a.key_package, self.crypto)
        members = list(group.iter_members())
        self.assertEqual(len(members), 1)
        self.assertEqual(members[0][0], 0)
        self.assertEqual(members[0][1], b"alice-id")


if __name__ == "__main__":
    unittest.main()

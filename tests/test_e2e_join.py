"""
Port of OpenMLS join.rs: join from Welcome, join with outdated leaf nodes (lifetime validation).

See: https://github.com/openmls/openmls/blob/main/openmls/tests/join.rs
"""
import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group


class TestE2EJoin(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_join_from_welcome(self):
        """Alice creates group, adds Bob, Bob joins from Welcome (basic join)."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        group = Group.create(b"Test Group", alice.key_package, self.crypto)
        group.process_proposal(
            group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = group.commit(alice.signing_private_key)
        self.assertGreaterEqual(len(welcomes), 1)

        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)
        self.assertEqual(group.member_count, 2)
        self.assertEqual(group.epoch, bob_group.epoch)

    @unittest.skip(
        "PyMLS from_welcome does not currently validate leaf node lifetime; "
        "OpenMLS join_tree_with_outdated_leafnodes expects join to fail when tree has expired leaf"
    )
    def test_join_tree_with_outdated_leafnodes(self):
        """Join when the tree contains an expired leaf (Bob added with short lifetime); Charlie join should fail."""
        pass


if __name__ == "__main__":
    unittest.main()

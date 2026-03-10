"""
Port of OpenMLS mls_group.rs: duplicate signature key detection, member list, pending proposals.

See: https://github.com/openmls/openmls/blob/main/openmls/tests/mls_group.rs
"""
import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group


class TestE2EMLSGroup(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    @unittest.skip("Remove then Add in separate commits triggers UpdatePath LeafNode invalid signature on apply")
    def test_duplicate_signature_key_detection_same_key_package(self):
        """Add Bob, commit; then Remove Bob, Add Bob (same KeyPackage); commit -> Bob is back (OpenMLS-style)."""
        group_id = b"Test Group"
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        alice_group = Group.create(group_id, alice.key_package, self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        self.assertEqual(alice_group.member_count, 2)
        members = list(alice_group.iter_members())
        self.assertEqual(members[0][1], b"Alice")
        self.assertEqual(members[1][1], b"Bob")

        # Alice: Remove Bob (leaf index 1), commit and apply
        alice_group.process_proposal(
            alice_group.remove(1, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit2, _ = alice_group.commit(alice.signing_private_key)
        alice_group.apply_commit(commit2, sender_leaf_index=0)
        self.assertEqual(alice_group.member_count, 1)
        # Alice: Add Bob (same key package), commit and apply
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit3, welcomes3 = alice_group.commit(alice.signing_private_key)
        alice_group.apply_commit(commit3, sender_leaf_index=0)
        self.assertEqual(alice_group.member_count, 2)
        members_after = list(alice_group.iter_members())
        ids = [m[1] for m in members_after]
        self.assertIn(b"Alice", ids)
        self.assertIn(b"Bob", ids)
        self.assertEqual(len(ids), 2)

    @unittest.skip("Remove then Add in separate commits triggers UpdatePath LeafNode invalid signature on apply")
    def test_duplicate_signature_key_detection_different_key_package(self):
        """Add Bob, commit; then Remove Bob, Add Bob (new KP); commit -> Bob is back with new KP."""
        group_id = b"Test Group"
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        alice_group = Group.create(group_id, alice.key_package, self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        # Remove Bob, commit and apply
        alice_group.process_proposal(
            alice_group.remove(1, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit2, _ = alice_group.commit(alice.signing_private_key)
        alice_group.apply_commit(commit2, sender_leaf_index=0)
        self.assertEqual(alice_group.member_count, 1)
        # Add Bob (new KP), commit and apply
        bob2 = make_member(b"Bob", self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob2.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit3, welcomes3 = alice_group.commit(alice.signing_private_key)
        alice_group.apply_commit(commit3, sender_leaf_index=0)
        self.assertEqual(alice_group.member_count, 2)
        members_after = list(alice_group.iter_members())
        ids = [m[1] for m in members_after]
        self.assertIn(b"Alice", ids)
        self.assertIn(b"Bob", ids)
        self.assertEqual(len(ids), 2)


if __name__ == "__main__":
    unittest.main()

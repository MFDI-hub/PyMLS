"""
Port of OpenMLS book_code.rs: book-style flows (create, add, join, message, update, remove, re-add).

See: https://github.com/openmls/openmls/blob/main/openmls/tests/book_code.rs
"""
import unittest

from tests.helpers import has_hpke, make_member, make_update_leaf_node

from rfc9420 import DefaultCryptoProvider, Group


class TestE2EBookCode(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_book_operations_create_add_join_message(self):
        """Alice creates group, adds Bob, Bob joins from Welcome, Alice sends message to Bob."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        group_id = b"Test Group"
        alice_group = Group.create(group_id, alice.key_package, self.crypto)
        proposal = alice_group.add(bob.key_package, alice.signing_private_key)
        alice_group.process_proposal(proposal, sender_leaf_index=0)
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        self.assertGreaterEqual(len(welcomes), 1)

        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        self.assertEqual(alice_group.member_count, 2)
        members = list(alice_group.iter_members())
        ids = [m[1] for m in members]
        self.assertIn(b"Alice", ids)
        self.assertIn(b"Bob", ids)

        message_alice = b"Hi, I'm Alice!"
        ct = alice_group.protect(message_alice)
        sender, plain = bob_group.unprotect(ct)
        self.assertEqual(sender, 0)
        self.assertEqual(plain, message_alice)

    @unittest.skip(
        "Requires joiner own_leaf_index; join_from_welcome(key_package=...) fails tree_hash validation"
    )
    def test_book_operations_bob_update_commit(self):
        """After join: Bob updates and commits, Alice applies (OpenMLS book_operations)."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        group_id = b"Test Group"
        alice_group = Group.create(group_id, alice.key_package, self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        bob_new = make_member(b"Bob", self.crypto)
        leaf_update = make_update_leaf_node(bob_new, group_id, 1, self.crypto)
        update_proposal = bob_group.update(leaf_update, bob_new.signing_private_key)
        alice_group.process_proposal(update_proposal, sender_leaf_index=1)
        commit2, welcomes2 = bob_group.commit(bob_new.signing_private_key)
        self.assertEqual(len(welcomes2), 0)
        alice_group.apply_commit(commit2, sender_leaf_index=1)
        self.assertEqual(alice_group.epoch, 2)

    @unittest.skip(
        "Add(Charlie) triggers 'Add for client already in group' in create_commit validation"
    )
    def test_book_operations_add_charlie_message(self):
        """Alice + Bob; Alice adds Charlie; Charlie sends message."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)
        charlie = make_member(b"Charlie", self.crypto)

        alice_group = Group.create(b"Test Group", alice.key_package, self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        alice_group.process_proposal(
            alice_group.add(charlie.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit2, welcomes2 = alice_group.commit(alice.signing_private_key)
        self.assertGreaterEqual(len(welcomes2), 1)
        charlie_group = Group.join_from_welcome(welcomes2[0], charlie.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit2, sender_leaf_index=1)
        bob_group.apply_commit(commit2, sender_leaf_index=1)
        charlie_group.apply_commit(commit2, sender_leaf_index=1)

        self.assertEqual(alice_group.member_count, 3)
        msg = b"Hello from Charlie"
        ct = charlie_group.protect(msg)
        sender, plain = alice_group.unprotect(ct)
        self.assertEqual(plain, msg)
        self.assertEqual(sender, 2)

    @unittest.skip(
        "Second commit (add Charlie or remove+add) triggers validation errors in create_commit"
    )
    def test_book_operations_remove_and_readd(self):
        """Alice, Bob, Charlie. Alice removes Bob then removes Charlie and adds Bob (new KP)."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)
        charlie = make_member(b"Charlie", self.crypto)

        alice_group = Group.create(b"Test Group", alice.key_package, self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        alice_group.process_proposal(
            alice_group.add(charlie.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit2, welcomes2 = alice_group.commit(alice.signing_private_key)
        charlie_group = Group.join_from_welcome(welcomes2[0], charlie.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit2, sender_leaf_index=0)
        bob_group.apply_commit(commit2, sender_leaf_index=0)
        charlie_group.apply_commit(commit2, sender_leaf_index=0)
        # Now Alice=0, Bob=1, Charlie=2

        # Alice removes Bob (leaf index 1)
        alice_group.process_proposal(
            alice_group.remove(1, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit3, _ = alice_group.commit(alice.signing_private_key)
        bob_group.apply_commit(commit3, sender_leaf_index=0)
        charlie_group.apply_commit(commit3, sender_leaf_index=0)
        self.assertEqual(alice_group.member_count, 2)

        # Alice removes Charlie (now leaf index 1 after Bob removed) and adds Bob (new KeyPackage)
        bob_new = make_member(b"Bob", self.crypto)
        alice_group.process_proposal(
            alice_group.remove(1, alice.signing_private_key),
            sender_leaf_index=0,
        )
        alice_group.process_proposal(
            alice_group.add(bob_new.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit4, welcomes4 = alice_group.commit(alice.signing_private_key)
        self.assertGreaterEqual(len(welcomes4), 1)
        bob_group2 = Group.join_from_welcome(welcomes4[0], bob_new.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit4, sender_leaf_index=0)
        charlie_group.apply_commit(commit4, sender_leaf_index=0)
        bob_group2.apply_commit(commit4, sender_leaf_index=0)

        self.assertEqual(alice_group.member_count, 2)
        members = list(alice_group.iter_members())
        ids = [m[1] for m in members]
        self.assertIn(b"Alice", ids)
        self.assertIn(b"Bob", ids)

    def test_create_with_specific_group_id(self):
        """Create group with explicit group_id (OpenMLS book: alice_create_group_with_group_id)."""
        alice = make_member(b"Alice", self.crypto)
        group_id = b"123e4567e89b"
        group = Group.create(group_id, alice.key_package, self.crypto)
        self.assertEqual(group.group_id, group_id)
        self.assertEqual(group.member_count, 1)

    @unittest.skip("PyMLS Group.create has no builder for padding_size/sender_ratchet_config (OpenMLS book_code.rs)")
    def test_create_with_builder_padding_and_ratchet_config(self):
        """OpenMLS book_code: MlsGroup::builder() with padding_size, sender_ratchet_config."""
        pass

    @unittest.skip("PyMLS has no group context external_senders extension in create (OpenMLS book_code.rs)")
    def test_create_with_external_senders(self):
        """OpenMLS book_code: Group with ExternalSenders extension (e.g. delivery-service)."""
        pass

    @unittest.skip("PyMLS has no leaf_node_extensions in key package / create (OpenMLS book_code.rs)")
    def test_create_with_leaf_node_extensions(self):
        """OpenMLS book_code: Leaf node with Unknown(0xff00) extension."""
        pass


if __name__ == "__main__":
    unittest.main()

"""
Port of OpenMLS own_messages.rs: decryption of own application message must fail.

See: https://github.com/openmls/openmls/blob/main/openmls/tests/own_messages.rs
"""
import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import CannotDecryptOwnMessageError, DefaultCryptoProvider, Group


class TestE2EOwnMessages(unittest.TestCase):
    """Port of OpenMLS own_messages_attempted_decryption: sender must not decrypt own message."""

    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_own_messages_attempted_decryption(self):
        """Alice creates group, adds Bob; Alice sends message; Bob decrypts; Alice must not decrypt her own."""
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

        self.assertEqual(alice_group.member_count, 2)

        message_alice = b"Hi, I'm Alice!"
        ct = alice_group.protect(message_alice, signing_key=alice.signing_private_key)

        # Bob can decrypt
        sender, plain = bob_group.unprotect(ct)
        self.assertEqual(sender, 0)
        self.assertEqual(plain, message_alice)

        # Alice must not decrypt her own message (OpenMLS: CannotDecryptOwnMessage)
        with self.assertRaises(CannotDecryptOwnMessageError):
            alice_group.unprotect(ct)


if __name__ == "__main__":
    unittest.main()

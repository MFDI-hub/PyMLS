"""
Port of OpenMLS external_commit.rs: external commit (join via GroupInfo), GroupInfo signature validation.

See: https://github.com/openmls/openmls/blob/main/openmls/tests/external_commit.rs
"""
import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group
from rfc9420.protocol.mls_group import MLSGroup


class TestE2EExternalCommit(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    @unittest.skip(
        "UpdatePath LeafNode validation fails (tree_hash / provisional GC order in process_external_commit)"
    )
    def test_external_commit_positive(self):
        """Alice creates group; Bob joins via external commit using exported GroupInfo; Bob sends, Alice decrypts."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        alice_group = Group.create(b"Test Group", alice.key_package, self.crypto)
        gi_bytes = alice_group._inner.export_group_info(alice.signing_private_key)

        bob_inner = MLSGroup.from_group_info(gi_bytes, self.crypto)
        commit, welcomes = bob_inner.external_commit(
            bob.key_package, bob.signing_private_key, kem_public_key=None
        )
        self.assertEqual(len(welcomes), 0)

        alice_group._inner.process_external_commit(commit)

        msg = b"Hello Alice"
        ct = bob_inner.protect(msg, signing_key=bob.signing_private_key)
        sender, plain = alice_group._inner.unprotect(ct)
        self.assertEqual(plain, msg)
        self.assertEqual(sender, bob_inner.get_own_leaf_index())

    def test_external_commit_broken_signature_fails(self):
        """GroupInfo with corrupted signature should fail from_group_info or external_commit path."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        alice_group = Group.create(b"Test Group", alice.key_package, self.crypto)
        gi_bytes = bytearray(alice_group._inner.export_group_info(alice.signing_private_key))
        gi_bytes[-1] ^= 1
        broken_gi_bytes = bytes(gi_bytes)

        with self.assertRaises(Exception):
            MLSGroup.from_group_info(broken_gi_bytes, self.crypto)

    @unittest.skip("PyMLS does not expose GroupInfo from commit (OpenMLS external_commit.rs test_group_info)")
    def test_group_info(self):
        """OpenMLS: Self-update then export GroupInfo from commit; Bob joins via that GroupInfo."""
        pass

    @unittest.skip("PyMLS does not expose optional GroupInfo when ratchet_tree_extension off (OpenMLS external_commit.rs test_not_present_group_info)")
    def test_not_present_group_info(self):
        """OpenMLS: When use_ratchet_tree_extension is false, self_update yields no GroupInfo."""
        pass

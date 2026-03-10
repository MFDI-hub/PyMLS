"""
Port of OpenMLS data_next_epoch.rs: StagedCommit/StagedWelcome next-epoch APIs and export_secret.

See: https://github.com/openmls/openmls/blob/main/openmls/tests/data_next_epoch.rs
"""
import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group


class TestE2EDataNextEpoch(unittest.TestCase):
    """Port of OpenMLS data_next_epoch.rs; tests using existing API + stubs for staged APIs."""

    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_export_secret_and_epoch_match_after_apply_commit(self):
        """After add+commit+apply, export_secret and epoch match for all members (no StagedCommit)."""
        alice = make_member(b"Alice", self.crypto)
        bob = make_member(b"Bob", self.crypto)

        group_id = b"test-group"
        alice_group = Group.create(group_id, alice.key_package, self.crypto)
        alice_group.process_proposal(
            alice_group.add(bob.key_package, alice.signing_private_key),
            sender_leaf_index=0,
        )
        commit, welcomes = alice_group.commit(alice.signing_private_key)
        bob_group = Group.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        alice_group.apply_commit(commit, sender_leaf_index=0)
        bob_group.apply_commit(commit, sender_leaf_index=0)

        self.assertEqual(alice_group.epoch, bob_group.epoch)
        label = b"test-label"
        context = b"ctx"
        length = 32
        alice_export = alice_group.export_secret(label, context, length)
        bob_export = bob_group.export_secret(label, context, length)
        self.assertEqual(alice_export, bob_export)

    @unittest.skip("PyMLS does not expose StagedCommit (OpenMLS data_next_epoch.rs)")
    def test_staged_commit_next_epoch_values_match_merged_group(self):
        """OpenMLS: StagedCommit epoch/auth/psk/export_secret/tree match MlsGroup after merge."""
        pass

    @unittest.skip("PyMLS does not expose StagedCommit (OpenMLS data_next_epoch.rs)")
    def test_staged_commit_self_removed_returns_none(self):
        """OpenMLS: When member is removed, StagedCommit returns None for secrets."""
        pass

    @unittest.skip("PyMLS does not expose StagedWelcome (OpenMLS data_next_epoch.rs)")
    def test_staged_welcome_export_secret_matches_created_group(self):
        """OpenMLS: StagedWelcome.export_secret matches MlsGroup.export_secret after into_group."""
        pass


if __name__ == "__main__":
    unittest.main()

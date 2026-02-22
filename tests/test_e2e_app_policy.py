import unittest
from datetime import datetime, timedelta, timezone

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider
from rfc9420.api import MLSGroupSession, MLSAppPolicy, MLSOrchestrator


class TestE2EAppPolicy(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def _build_two_party_sessions(self):
        alice = make_member(b"alice", self.crypto)
        bob = make_member(b"bob", self.crypto)

        a = MLSGroupSession.create(b"policy-group", alice.key_package, self.crypto)
        proposal_bytes = a.add_member(bob.key_package, alice.signing_private_key)
        a.process_proposal(proposal_bytes, sender_leaf_index=0)
        commit_bytes, welcomes = a.commit(alice.signing_private_key)
        b = MLSGroupSession.join_from_welcome(welcomes[0], bob.hpke_private_key, self.crypto)
        b.apply_commit(commit_bytes, sender_leaf_index=0)
        return a, b

    def test_runtime_policy_plumbing(self):
        policy = MLSAppPolicy(
            secret_tree_window_size=33,
            max_generation_gap=77,
            aead_limit_bytes=1024,
        )
        alice = make_member(b"alice", self.crypto)
        s = MLSGroupSession.create(b"policy-plumb", alice.key_package, self.crypto, policy=policy)
        effective = s.get_effective_policy()
        self.assertEqual(effective["secret_tree_window_size"], 33)
        self.assertEqual(effective["max_generation_gap"], 77)
        self.assertEqual(effective["aead_limit_bytes"], 1024)

    def test_aead_limit_blocks_large_message(self):
        a, _b = self._build_two_party_sessions()
        policy = MLSAppPolicy(aead_limit_bytes=3)
        a.apply_policy(policy)
        with self.assertRaises(Exception):
            a.protect_application(b"1234")

    def test_policy_orchestrator_rotation_and_retention(self):
        a, _b = self._build_two_party_sessions()
        policy = MLSAppPolicy(update_interval_seconds=60, max_resumption_epochs=2)
        orch = MLSOrchestrator(a, policy)

        start = datetime.now(timezone.utc)
        self.assertFalse(orch.should_rotate_now(now=start))
        self.assertTrue(orch.should_rotate_now(now=start + timedelta(seconds=61)))

        orch.record_resumption_psk(1, b"a")
        orch.record_resumption_psk(2, b"b")
        orch.record_resumption_psk(3, b"c")
        kept = orch.list_resumption_psks()
        self.assertEqual([epoch for epoch, _ in kept], [2, 3])

    def test_conflict_selection_deterministic_hash(self):
        a, _b = self._build_two_party_sessions()
        policy = MLSAppPolicy(conflict_resolution_strategy="deterministic_hash")
        orch = MLSOrchestrator(a, policy)
        epoch = a.epoch
        orch._pending_commit_bytes[epoch] = b"\xff\x00"
        chosen = orch._pick_commit(epoch, b"\x00\xff", sender_leaf_index=1)
        self.assertEqual(chosen, b"\x00\xff")


if __name__ == "__main__":
    unittest.main()

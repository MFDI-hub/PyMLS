import unittest

from src.pymls.codec.mls import (
    encode_commit_message,
    decode_commit_message,
    encode_proposals_message,
    decode_proposals_message,
    MLSMessage,
    MLSContentType,
)
from src.pymls.protocol.data_structures import Commit, UpdatePath, Signature, AddProposal, Proposal


class TestMLSCodec(unittest.TestCase):
    def test_commit_roundtrip(self):
        commit = Commit(path=None, removes=[], adds=[], proposal_refs=[], signature=Signature(b""))
        sig = b"sig"
        data = encode_commit_message(commit, sig)
        c2, s2 = decode_commit_message(data)
        self.assertEqual(c2.removes, [])
        self.assertEqual(c2.adds, [])
        self.assertEqual(s2, sig)

    def test_proposals_roundtrip(self):
        kp_bytes = b"kp"
        proposals = [AddProposal(kp_bytes)]
        sig = b"sig"
        data = encode_proposals_message(proposals, sig)
        p2, s2 = decode_proposals_message(data)
        self.assertEqual(len(p2), 1)
        self.assertIsInstance(p2[0], AddProposal)
        self.assertEqual(s2, sig)


if __name__ == "__main__":
    unittest.main()


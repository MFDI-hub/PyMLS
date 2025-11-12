import unittest
from pymls.protocol.validations import (
    validate_proposals_client_rules,
    validate_commit_matches_referenced_proposals,
    CommitValidationError,
)
from pymls.protocol.data_structures import AddProposal, RemoveProposal, UpdateProposal, Commit, Signature


class TestValidations(unittest.TestCase):
    def test_unique_adds_by_user(self):
        proposals = [AddProposal(b"kpA"), AddProposal(b"kpA")]
        with self.assertRaises(CommitValidationError):
            validate_proposals_client_rules(proposals, 1)

    def test_remove_bounds(self):
        proposals = [RemoveProposal(2)]
        with self.assertRaises(CommitValidationError):
            validate_proposals_client_rules(proposals, 1)

    def test_commit_matches_refs(self):
        proposals = [AddProposal(b"kp"), RemoveProposal(0), UpdateProposal(b"ln")]
        commit = Commit(path=None, removes=[0], adds=[b"kp"], proposal_refs=[], signature=Signature(b""))
        # No refs: skip check. Now pretend refs resolved
        validate_commit_matches_referenced_proposals(commit, proposals)
        bad = Commit(path=None, removes=[], adds=[b"kp"], proposal_refs=[], signature=Signature(b""))
        with self.assertRaises(CommitValidationError):
            validate_commit_matches_referenced_proposals(bad, proposals)


if __name__ == "__main__":
    unittest.main()



import unittest
from pymls.protocol.validations import (
    validate_proposals_client_rules,
    validate_commit_matches_referenced_proposals,
    CommitValidationError,
)
from pymls.protocol.data_structures import AddProposal, RemoveProposal, UpdateProposal, Commit, Signature, ProposalOrRef, ProposalOrRefType


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
        # Build a commit with proposals by-value (no references) -> should pass even if 'referenced' empty
        by_value = [
            ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=RemoveProposal(0)),
            ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=AddProposal(b"kp")),
        ]
        commit_no_refs = Commit(path=None, proposals=by_value, signature=Signature(b""))
        validate_commit_matches_referenced_proposals(commit_no_refs, proposals)
        # Build a commit that carries a reference but provide no resolved proposals -> should raise
        with_refs = [ProposalOrRef(ProposalOrRefType.REFERENCE, reference=b"abc")]
        commit_with_ref = Commit(path=None, proposals=with_refs, signature=Signature(b""))
        with self.assertRaises(CommitValidationError):
            validate_commit_matches_referenced_proposals(commit_with_ref, [])


if __name__ == "__main__":
    unittest.main()



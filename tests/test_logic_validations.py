import unittest

from rfc9420.protocol.data_structures import (
    AddProposal,
    Commit,
    ProposalOrRef,
    ProposalOrRefType,
    RemoveProposal,
    UpdateProposal,
)
from rfc9420.protocol.validations import (
    CommitValidationError,
    validate_commit_matches_referenced_proposals,
    validate_proposals_client_rules,
)


class TestLogicValidations(unittest.TestCase):
    def test_duplicate_add_by_user_rejected(self):
        proposals = [AddProposal(b"same-user"), AddProposal(b"same-user")]
        with self.assertRaises(CommitValidationError):
            validate_proposals_client_rules(proposals, n_leaves=1)

    def test_remove_index_bounds_rejected(self):
        with self.assertRaises(CommitValidationError):
            validate_proposals_client_rules([RemoveProposal(9)], n_leaves=1)

    def test_commit_references_must_resolve(self):
        referenced = [AddProposal(b"kp"), RemoveProposal(0), UpdateProposal(b"ln")]
        ok = Commit(
            path=None,
            proposals=[ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=RemoveProposal(0))],
        )
        validate_commit_matches_referenced_proposals(ok, referenced)

        bad = Commit(
            path=None,
            proposals=[ProposalOrRef(ProposalOrRefType.REFERENCE, reference=b"\x01")],
        )
        with self.assertRaises(CommitValidationError):
            validate_commit_matches_referenced_proposals(bad, [])


if __name__ == "__main__":
    unittest.main()

"""
Port of OpenMLS book_code_discard_commit.rs and book_code_discard_welcome.rs.

Discard pending commit / discard Welcome (clear_pending_commit, inspect Welcome without joining).
See: https://github.com/openmls/openmls/blob/main/openmls/tests/book_code_discard_commit.rs
See: https://github.com/openmls/openmls/blob/main/openmls/tests/book_code_discard_welcome.rs
"""
import unittest

from tests.helpers import has_hpke

from rfc9420 import DefaultCryptoProvider


class TestE2EBookCodeDiscardCommit(unittest.TestCase):
    """Stubs for OpenMLS book_code_discard_commit.rs: clear_pending_commit after add/update/remove/PSK/etc."""

    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_add(self):
        """OpenMLS: After add_members, clear_pending_commit; state rolls back."""
        pass

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_update_with_new_signer(self):
        """OpenMLS: After self_update_with_new_signer, clear_pending_commit; signer/leaf unchanged."""
        pass

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_remove(self):
        """OpenMLS: After remove_members, clear_pending_commit; state rolls back."""
        pass

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_psk(self):
        """OpenMLS: After propose_external_psk + commit, clear_pending_commit; delete_psk + clear."""
        pass

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_external_join(self):
        """OpenMLS: After external_commit, delete MlsGroup; storage state unchanged."""
        pass

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_group_context_extensions(self):
        """OpenMLS: After propose_group_context_extensions + commit, clear_pending_commit."""
        pass

    @unittest.skip("PyMLS has no clear_pending_commit API (OpenMLS book_code_discard_commit.rs)")
    def test_discard_commit_custom_proposal(self):
        """OpenMLS: After propose_custom_proposal_by_value + commit, clear_pending_commit."""
        pass


class TestE2EBookCodeDiscardWelcome(unittest.TestCase):
    """Stubs for OpenMLS book_code_discard_welcome.rs: inspect Welcome without joining."""

    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    @unittest.skip("PyMLS has no discard Welcome / StagedWelcome-without-into_group API (OpenMLS book_code_discard_welcome.rs)")
    def test_not_join_group(self):
        """OpenMLS: Process Welcome into ProcessedWelcome/StagedWelcome, inspect only; never into_group."""
        pass


if __name__ == "__main__":
    unittest.main()

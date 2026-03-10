"""
Skipped stubs for OpenMLS tests that require extensions or features not yet implemented in PyMLS.

See: https://github.com/openmls/openmls/tree/main/openmls/tests
"""
import unittest


class TestOpenMLSUnsupportedStubs(unittest.TestCase):
    """Placeholder tests for OpenMLS scenarios not yet supported; skip with reason."""

    @unittest.skip("PyMLS has no AppDataDictionary / AppDataUpdate extension (OpenMLS app_data_update.rs)")
    def test_app_data_update_simple(self):
        """OpenMLS: AppDataUpdate proposal and commit with app data dictionary."""
        pass

    @unittest.skip("PyMLS has no AppDataDictionary extension (OpenMLS app_data_update.rs)")
    def test_app_data_update_with_welcome(self):
        """OpenMLS: AppDataUpdate combined with Add proposal in same commit."""
        pass

    @unittest.skip("PyMLS has no app-ephemeral / ephemeral feature (OpenMLS app_ephemeral.rs)")
    def test_app_ephemeral(self):
        """OpenMLS: Ephemeral / app-ephemeral feature."""
        pass

    @unittest.skip("Optional: book_code_discard_commit / discard_welcome / fork_resolution (OpenMLS book_code_*.rs)")
    def test_book_code_discard_commit(self):
        """OpenMLS: Discard commit flow."""
        pass

    @unittest.skip("Optional: GREASE, interop_scenarios, managed_api, etc. (OpenMLS tests)")
    def test_grease_extensions(self):
        """OpenMLS: GREASE extension handling."""
        pass


if __name__ == "__main__":
    unittest.main()

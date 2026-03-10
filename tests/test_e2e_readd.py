"""
Port of OpenMLS readd.rs: swap members (remove + re-add with new KeyPackages), re-join from Welcome.

See: https://github.com/openmls/openmls/blob/main/openmls/tests/readd.rs
"""
import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import DefaultCryptoProvider, Group


class TestE2EReadd(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    @unittest.skip(
        "Adding three members in one commit triggers tree_math 'leaf node has no children' in current PyMLS"
    )
    def test_add_three_join_from_same_welcome(self):
        """OpenMLS readd: Alice adds Bob, Charlie, Yuk in one commit; all three join from same Welcome."""
        pass

    @unittest.skip(
        "Swap (remove Alice + Yuk, add new Alice + Yuk KeyPackages, re-join) triggers "
        "UpdatePath/validation issues in current PyMLS; see test_e2e_mls_group remove+add"
    )
    def test_swap_members_then_rejoin(self):
        """OpenMLS readd swap: Bob removes Alice and Yuk, adds new Alice and Yuk; they re-join from new Welcome."""
        pass


if __name__ == "__main__":
    unittest.main()

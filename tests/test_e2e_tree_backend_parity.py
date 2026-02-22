import unittest

from tests.helpers import has_hpke, make_member

from rfc9420 import (
    BACKEND_ARRAY,
    BACKEND_LINKED,
    BACKEND_PERFECT,
    DefaultCryptoProvider,
    Group,
)


class TestE2ETreeBackendParity(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")
        self.crypto = DefaultCryptoProvider()

    def test_create_group_with_each_backend(self):
        for backend in [BACKEND_ARRAY, BACKEND_PERFECT, BACKEND_LINKED]:
            member = make_member(f"user-{backend}".encode(), self.crypto)
            group = Group.create(
                group_id=f"backend-{backend}".encode(),
                key_package=member.key_package,
                crypto=self.crypto,
                tree_backend=backend,
            )
            self.assertEqual(group.epoch, 0)
            self.assertEqual(group.member_count, 1)
            self.assertEqual(group.group_id, f"backend-{backend}".encode())


if __name__ == "__main__":
    unittest.main()

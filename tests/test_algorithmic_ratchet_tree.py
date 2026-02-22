import unittest

from rfc9420 import DefaultCryptoProvider
from rfc9420.protocol.ratchet_tree import RatchetTree
from tests.helpers import make_member


class TestAlgorithmicRatchetTree(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        self.tree = RatchetTree(self.crypto)

    def test_add_and_tree_hash(self):
        a = make_member(b"a", self.crypto).key_package
        idx = self.tree.add_leaf(a)
        self.assertEqual(idx, 0)
        self.assertTrue(self.tree.calculate_tree_hash())

    def test_update_path_creation_returns_secret(self):
        a = make_member(b"a", self.crypto).key_package
        b = make_member(b"b", self.crypto).key_package
        self.tree.add_leaf(a)
        self.tree.add_leaf(b)
        leaf_node = self.tree.get_node(0).leaf_node
        assert leaf_node is not None
        update_path, _ = self.tree.create_update_path(0, leaf_node, b"context")
        self.assertIsNotNone(update_path)

    def test_welcome_tree_serialization_non_empty(self):
        self.tree.add_leaf(make_member(b"a", self.crypto).key_package)
        self.tree.add_leaf(make_member(b"b", self.crypto).key_package)
        blob = self.tree.serialize_tree_for_welcome()
        self.assertIsInstance(blob, bytes)
        self.assertGreater(len(blob), 0)


if __name__ == "__main__":
    unittest.main()

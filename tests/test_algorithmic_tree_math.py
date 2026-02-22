import unittest

from rfc9420.protocol.tree_math import (
    copath,
    direct_path,
    level,
    log2,
    node_width,
    parent,
    sibling,
)


class TestAlgorithmicTreeMath(unittest.TestCase):
    def test_log2_and_level(self):
        self.assertEqual(log2(1), 0)
        self.assertEqual(log2(8), 3)
        self.assertEqual(level(0), 0)  # leaf
        self.assertEqual(level(3), 2)  # internal

    def test_node_width_formula(self):
        for leaves in range(1, 16):
            self.assertEqual(node_width(leaves), 2 * (leaves - 1) + 1)

    def test_direct_path_and_copath_lengths_match(self):
        n = 8
        for leaf in [0, 2, 4, 6]:
            dp = direct_path(leaf, n)
            cp = copath(leaf, n)
            self.assertEqual(len(dp), len(cp))
            if dp:
                self.assertEqual(cp[0], sibling(leaf, n))
                self.assertEqual(parent(leaf, n), dp[0])


if __name__ == "__main__":
    unittest.main()

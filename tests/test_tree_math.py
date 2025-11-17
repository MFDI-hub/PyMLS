"""Comprehensive tests for pymls.protocol.tree_math module."""
import unittest

from pymls.protocol.tree_math import (
    log2,
    level,
    node_width,
    root,
    left,
    right,
    parent,
    sibling,
    direct_path,
    copath,
)
from pymls.mls.exceptions import PyMLSError


class TestTreeMath(unittest.TestCase):
    def test_log2(self):
        """Test log2 function."""
        self.assertEqual(log2(0), 0)
        self.assertEqual(log2(1), 0)
        self.assertEqual(log2(2), 1)
        self.assertEqual(log2(3), 1)
        self.assertEqual(log2(4), 2)
        self.assertEqual(log2(5), 2)
        self.assertEqual(log2(7), 2)
        self.assertEqual(log2(8), 3)
        self.assertEqual(log2(15), 3)
        self.assertEqual(log2(16), 4)

    def test_level(self):
        """Test level function."""
        # Even indices are leaves (level 0)
        self.assertEqual(level(0), 0)
        self.assertEqual(level(2), 0)
        self.assertEqual(level(4), 0)
        self.assertEqual(level(6), 0)
        
        # Odd indices are internal nodes
        self.assertEqual(level(1), 1)
        self.assertEqual(level(3), 2)
        self.assertEqual(level(5), 1)
        self.assertEqual(level(7), 3)

    def test_node_width(self):
        """Test node_width function."""
        self.assertEqual(node_width(0), 0)
        self.assertEqual(node_width(1), 1)
        self.assertEqual(node_width(2), 3)
        self.assertEqual(node_width(3), 5)
        self.assertEqual(node_width(4), 7)
        self.assertEqual(node_width(5), 9)
        # Formula: 2 * (n - 1) + 1
        for n in range(1, 20):
            self.assertEqual(node_width(n), 2 * (n - 1) + 1)

    def test_root(self):
        """Test root function."""
        self.assertEqual(root(0), 0)
        self.assertEqual(root(1), 0)
        self.assertEqual(root(2), 1)
        self.assertEqual(root(3), 3)
        self.assertEqual(root(4), 3)
        self.assertEqual(root(5), 7)
        self.assertEqual(root(8), 7)

    def test_left(self):
        """Test left function."""
        # Left child of node 1 (level 1) should be 0
        self.assertEqual(left(1), 0)
        # Left child of node 3 (level 2) should be 1
        self.assertEqual(left(3), 1)
        # Left child of node 5 (level 1) should be 4
        self.assertEqual(left(5), 4)
        
        # Leaf nodes should raise error
        with self.assertRaises(PyMLSError):
            left(0)
        with self.assertRaises(PyMLSError):
            left(2)

    def test_right(self):
        """Test right function."""
        # Right child of node 1 (level 1) should be 2
        self.assertEqual(right(1, 3), 2)
        # Right child of node 3 (level 2) should be 5
        self.assertEqual(right(3, 7), 5)
        
        # Leaf nodes should raise error
        with self.assertRaises(PyMLSError):
            right(0, 3)
        with self.assertRaises(PyMLSError):
            right(2, 3)

    def test_parent(self):
        """Test parent function."""
        # Parent of leaf 0 should be 1
        self.assertEqual(parent(0, 2), 1)
        # Parent of leaf 2 should be 1
        self.assertEqual(parent(2, 2), 1)
        # Parent of leaf 4 should be 5
        self.assertEqual(parent(4, 5), 5)
        
        # Root node should raise error
        with self.assertRaises(PyMLSError):
            parent(1, 2)  # 1 is root for n=2

    def test_sibling(self):
        """Test sibling function."""
        # Sibling of 0 should be 2 (both children of 1)
        self.assertEqual(sibling(0, 2), 2)
        # Sibling of 2 should be 0
        self.assertEqual(sibling(2, 2), 0)
        # Sibling of 4 should be 6 (both children of 5)
        self.assertEqual(sibling(4, 5), 6)

    def test_direct_path(self):
        """Test direct_path function."""
        # Direct path from root should be empty
        self.assertEqual(direct_path(1, 2), [])
        
        # Direct path from leaf 0 in tree of 2 leaves
        path = direct_path(0, 2)
        self.assertEqual(path, [1])  # Path to root (excluding root)
        
        # Direct path from leaf 4 in tree of 5 leaves
        path = direct_path(4, 5)
        # Should go: 4 -> 5 -> 7 (root is 7, so path is [5, 7])
        self.assertIn(5, path)
        self.assertIn(7, path)

    def test_copath(self):
        """Test copath function."""
        # Copath from root should be empty
        self.assertEqual(copath(1, 2), [])
        
        # Copath from leaf 0 in tree of 2 leaves
        cop = copath(0, 2)
        # Should include sibling of nodes on direct path
        self.assertEqual(cop, [2])  # Sibling of 0
        
        # Copath from leaf 4 in tree of 5 leaves
        cop = copath(4, 5)
        # Should include siblings along the path
        self.assertGreater(len(cop), 0)

    def test_tree_structure_consistency(self):
        """Test that tree structure functions are consistent."""
        n = 8
        r = root(n)
        
        # Root should have no parent
        with self.assertRaises(PyMLSError):
            parent(r, n)
        
        # For each leaf, verify parent-child relationships
        for leaf in range(0, n, 2):  # Even indices are leaves
            p = parent(leaf, n)
            # Parent's left or right child should be the leaf
            left_child = left(p) if p % 2 == 1 else None
            right_child = right(p, n) if p % 2 == 1 else None
            self.assertTrue(leaf == left_child or leaf == right_child)
            
            # Sibling should be the other child
            s = sibling(leaf, n)
            self.assertNotEqual(s, leaf)
            self.assertEqual(parent(s, n), p)

    def test_direct_path_and_copath_relationship(self):
        """Test that direct_path and copath are related correctly."""
        n = 8
        for leaf in range(0, n, 2):
            dp = direct_path(leaf, n)
            cp = copath(leaf, n)
            
            # Copath should have same length as direct_path
            self.assertEqual(len(cp), len(dp))
            
            # Each copath node should be sibling of corresponding direct_path node
            for i, dp_node in enumerate(dp):
                cp_node = cp[i]
                self.assertEqual(sibling(dp_node, n), cp_node)


if __name__ == "__main__":
    unittest.main()


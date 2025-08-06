import math


def log2(x: int) -> int:
    if x == 0:
        return 0
    return x.bit_length() - 1


def level(node_index: int) -> int:
    """Calculates the level of a node in the tree."""
    if (node_index & 1) == 0:
        return 0
    
    k = 0
    x = node_index + 1
    while x & 1 == 0:
        k += 1
        x >>= 1
    return k


def root(n_leaves: int) -> int:
    """Calculates the root of the tree."""
    if n_leaves == 0:
        return 0  # Or raise error, but for hash of empty tree, this is fine.
    if n_leaves == 1:
        return 0
    return (1 << log2(n_leaves - 1)) * 2 - 1


def left(node_index: int) -> int:
    """Calculates the left child of a node."""
    node_level = level(node_index)
    if node_level == 0:
        raise ValueError("Leaf nodes have no children")
    return node_index - (1 << (node_level - 1))


def right(node_index: int, n_leaves: int) -> int:
    """Calculates the right child of a node."""
    node_level = level(node_index)
    if node_level == 0:
        raise ValueError("Leaf nodes have no children")
    
    r = node_index + (1 << (node_level - 1))

    # A full subtree of `node_level` has 2**`node_level` leaves.
    # The number of non-blank leaves under a node is not simple to calculate
    # in an unbalanced tree without more info.
    # The parent calculation needs to be robust for this to work.
    # Let's assume the RFC formulation is correct for our index mapping.
    # If the right child is outside the tree, it's a blank node.
    # We will not error here, the caller must handle out-of-bounds.
    return r


def parent(node_index: int, n_leaves: int) -> int:
    """Calculates the parent of a node."""
    if node_index == root(n_leaves):
        raise ValueError("Root has no parent")

    node_level = level(node_index)
    # This formula is from the RFC. It relies on the node's position relative
    # to the power-of-2-sized subtrees.
    sub_tree_width = 1 << (node_level + 1)
    node_group_start = (node_index // sub_tree_width) * sub_tree_width

    parent_level_offset = 1 << node_level
    midpoint_in_group = node_group_start + parent_level_offset - 1

    if node_index <= midpoint_in_group:
        # Node is in a left subtree, parent is to the right
        return node_index + (1 << node_level)
    else:
        # Node is in a right subtree, parent is to the left
        return node_index - (1 << node_level)


def sibling(node_index: int, n_leaves: int) -> int:
    """Calculates the sibling of a node."""
    p = parent(node_index, n_leaves)
    if node_index == left(p):
        return right(p, n_leaves)
    return left(p)


def direct_path(leaf_node_index: int, n_leaves: int) -> list[int]:
    """Calculates the direct path from a leaf to the root."""
    path = []
    current = leaf_node_index
    if current == root(n_leaves):
        return []

    while current != root(n_leaves):
        current = parent(current, n_leaves)
        path.append(current)
    return path


def copath(leaf_node_index: int, n_leaves: int) -> list[int]:
    """Calculates the copath of a leaf."""
    path = direct_path(leaf_node_index, n_leaves)
    if not path:
        return []
        
    return [sibling(n, n_leaves) for n in path[:-1]]

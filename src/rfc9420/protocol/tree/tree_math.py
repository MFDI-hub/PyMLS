"""Array-indexed balanced binary tree helpers (RFC 9420 Appendix C)."""
from ...mls.exceptions import RFC9420Error


def log2(x: int) -> int:
    """Return floor(log2(x)) for positive integers; 0 for x == 0.

    Parameters
    ----------
    x : int
        Non-negative integer.

    Returns
    -------
    int
        floor(log2(x)), or 0 if x == 0.
    """
    # Equivalent to floor(log2(x))
    if x == 0:
        return 0
    k = 0
    while (x >> k) > 0:
        k += 1
    return k - 1


def level(x: int) -> int:
    """Level of a node in an array-based balanced tree.

    Leaves are level 0. For odd indices, count trailing ones in (x >> k) & 1.
    RFC 9420 Appendix C.

    Parameters
    ----------
    x : int
        Node array index.

    Returns
    -------
    int
        Level of the node (0 for leaves).
    """
    if x & 0x01 == 0:
        return 0

    k = 0
    while ((x >> k) & 0x01) == 1:
        k += 1
    return k


def node_width(n: int) -> int:
    """Total number of array nodes for a tree with n leaves.

    Parameters
    ----------
    n : int
        Number of leaves.

    Returns
    -------
    int
        Total node count (0 if n == 0).
    """
    if n == 0:
        return 0
    else:
        return 2 * (n - 1) + 1


def root(n: int) -> int:
    """Array index of the root for a tree with n leaves (0 if n == 0).

    Parameters
    ----------
    n : int
        Number of leaves.

    Returns
    -------
    int
        Root node index.
    """
    w = node_width(n)
    if w == 0:
        return 0
    return (1 << log2(w)) - 1


def left(x: int) -> int:
    """Left child index of internal node x.

    Parameters
    ----------
    x : int
        Internal node array index.

    Returns
    -------
    int
        Left child index.

    Raises
    ------
    RFC9420Error
        If x is a leaf (no children).
    """
    k = level(x)
    if k == 0:
        raise RFC9420Error("leaf node has no children")
    return x ^ (0x01 << (k - 1))


def right(x: int, n: int) -> int:
    """Right child index of internal node x.

    For non-power-of-2 leaf counts, the result is clamped to stay within
    the tree (repeated left steps) so that the index is < node_width(n).

    Parameters
    ----------
    x : int
        Internal node array index.
    n : int
        Number of leaves.

    Returns
    -------
    int
        Right child index (possibly clamped).

    Raises
    ------
    RFC9420Error
        If x is a leaf (no children).
    """
    k = level(x)
    if k == 0:
        raise RFC9420Error("leaf node has no children")
    r = x ^ (0x03 << (k - 1))
    w = node_width(n)
    while r >= w:
        r = left(r)
    return r


def parent(x: int, n: int) -> int:
    """Parent index of node x for a tree with n leaves.

    Parameters
    ----------
    x : int
        Node array index.
    n : int
        Number of leaves.

    Returns
    -------
    int
        Parent node index.

    Raises
    ------
    RFC9420Error
        If x is the root (no parent).
    """
    if x == root(n):
        raise RFC9420Error("root node has no parent")

    k = level(x)
    b = (x >> (k + 1)) & 0x01
    return (x | (1 << k)) ^ (b << (k + 1))


def sibling(x: int, n: int) -> int:
    """Sibling index of node x for a tree with n leaves.

    Parameters
    ----------
    x : int
        Node array index.
    n : int
        Number of leaves.

    Returns
    -------
    int
        Sibling node index.
    """
    p = parent(x, n)
    if x < p:
        return right(p, n)
    else:
        return left(p)


def direct_path(x: int, n: int) -> list[int]:
    """Indices on the path from node x up to and including the root.

    Parameters
    ----------
    x : int
        Node array index.
    n : int
        Number of leaves.

    Returns
    -------
    list[int]
        Path from x toward root (excluding x).
    """
    r = root(n)
    if x == r:
        return []

    d: list[int] = []
    while x != r:
        x = parent(x, n)
        d.append(x)
    return d


def copath(x: int, n: int) -> list[int]:
    """Sequence of sibling nodes along the path from x to the root (RFC 9420 §4.1.2).

    Parameters
    ----------
    x : int
        Node array index.
    n : int
        Number of leaves.

    Returns
    -------
    list[int]
        Copath sibling indices.
    """
    if x == root(n):
        return []

    r = root(n)
    path_from_x = [x] + [y for y in direct_path(x, n) if y != r]
    return [sibling(y, n) for y in path_from_x]


def lca(node_a: int, node_b: int, n: int) -> int:
    """Lowest common ancestor of two nodes (RFC 9420 §12.4.3: path_secret for joiner's LCA).

    Parameters
    ----------
    node_a : int
        First node array index.
    node_b : int
        Second node array index.
    n : int
        Number of leaves.

    Returns
    -------
    int
        LCA node index.
    """
    path_a = [node_a] + direct_path(node_a, n)
    path_b_set = {node_b}
    path_b_set.update(direct_path(node_b, n))
    for node in path_a:
        if node in path_b_set:
            return node
    return root(n)

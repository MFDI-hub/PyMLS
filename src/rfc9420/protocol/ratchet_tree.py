"""Ratchet tree representation and update path processing (RFC 9420 Appendix C).

This module provides a minimal array-indexed tree with helpers for adding,
removing, and updating leaves, computing node hashes, and producing/merging
UpdatePath structures used in commits.
"""

from typing import Any, Optional, Set, cast, List
from .key_packages import KeyPackage, LeafNode, LeafNodeSource
from ..codec.tls import (
    write_uint8,
    write_uint16,
    write_uint32,
    write_varint,
    write_opaque16,
    read_uint8,
    read_uint16,
    read_opaque16,
    write_opaque_varint,
    read_opaque_varint,
    read_varint,
    read_uint32,
)
from .data_structures import UpdatePath, Signature, serialize_bytes, UpdatePathNode
from . import tree_math
from ..crypto.crypto_provider import CryptoProvider
from ..crypto.hpke_labels import encrypt_with_label, decrypt_with_label
from ..crypto import labels as mls_labels
from ..mls.exceptions import CommitValidationError
import os


class RatchetTreeNode:
    """A single node in the array-indexed ratchet tree.

    Fields
    - is_leaf: True for leaf nodes (even indices), False otherwise.
    - public_key/private_key: Node key material (internal nodes derived from path secrets).
    - parent_hash: Optional parent hash for leaf binding.
    - leaf_node: Serialized leaf node metadata for leaves (KeyPackage.leaf_node).
    - hash: Cached node hash for tree hashing.
    """

    def __init__(self, is_leaf: bool):
        self.is_leaf = is_leaf
        self.public_key: Optional[bytes] = None
        self.private_key: Optional[bytes] = None
        self.parent_hash: Optional[bytes] = None
        self.leaf_node: Optional[LeafNode] = None
        self.hash: Optional[bytes] = None
        # RFC ?7.1: track unmerged leaves for parent nodes
        self.unmerged_leaves: list[int] = [] if not is_leaf else []


class RatchetTree:
    """Array-indexed ratchet tree with hashing and path operations."""

    backend_id = "array"

    def __init__(self, crypto_provider: CryptoProvider):
        """Create an empty ratchet tree."""
        self._n_leaves = 0
        self._nodes: dict[int, RatchetTreeNode] = {}
        self._crypto_provider = crypto_provider

    @property
    def n_leaves(self):
        """Current number of leaves in the tree."""
        return self._n_leaves

    def get_node(self, index: int) -> RatchetTreeNode:
        """Return the node at the given array index, creating a blank node if missing."""
        if index not in self._nodes:
            # Create blank nodes on demand. A node is a leaf if its index is even.
            self._nodes[index] = RatchetTreeNode(index % 2 == 0)
        return self._nodes[index]

    def add_leaf(self, key_package: KeyPackage) -> int:
        """Place new leaf at leftmost blank position (RFC ?12.1.1), or extend tree.

        After placement, all non-blank ancestors on the direct path have the new
        leaf index appended to their unmerged_leaves list (RFC ?7.1).
        """
        if key_package.leaf_node is None:
            raise ValueError("KeyPackage.leaf_node must be present to add a leaf")

        # Find leftmost blank leaf (RFC ?12.1.1)
        leaf_index: Optional[int] = None
        for i in range(self._n_leaves):
            node = self.get_node(i * 2)
            if node.leaf_node is None and node.public_key is None:
                leaf_index = i
                break
        if leaf_index is None:
            # No blank leaf found ? extend tree capacity
            leaf_index = self._n_leaves
            if self._n_leaves == 0:
                self._n_leaves = 1
            else:
                self._n_leaves *= 2

        node_index = leaf_index * 2
        node = self.get_node(node_index)
        node.public_key = key_package.leaf_node.encryption_key
        node.leaf_node = key_package.leaf_node

        # RFC ?7.1: add new leaf index to unmerged_leaves of non-blank ancestors
        for ancestor_idx in tree_math.direct_path(node_index, self._n_leaves):
            ancestor = self.get_node(ancestor_idx)
            if ancestor.public_key is not None:
                if leaf_index not in ancestor.unmerged_leaves:
                    ancestor.unmerged_leaves.append(leaf_index)
                    ancestor.unmerged_leaves.sort()

        self._recalculate_hashes_from(node_index)
        return leaf_index

    def remove_leaf(self, index: int) -> None:
        """Blank a leaf and its direct path; then resize to 2^d leaves (RFC ?12.1.3)."""
        node_index = index * 2
        node = self.get_node(node_index)
        node.public_key = None
        node.private_key = None
        node.leaf_node = None

        # Blank the direct path (RFC ?12.1.3)
        for p_idx in tree_math.direct_path(node_index, self.n_leaves):
            p_node = self.get_node(p_idx)
            p_node.public_key = None
            p_node.private_key = None
            p_node.parent_hash = b""

        self._recalculate_hashes_from(node_index)

        # RFC ?12.1.3: truncate to smallest 2^d where 2^d >= (rightmost non-blank leaf + 1)
        rightmost = -1
        for i in range(self._n_leaves - 1, -1, -1):
            n = self.get_node(i * 2)
            if n.leaf_node is not None or n.public_key is not None:
                rightmost = i
                break
        if rightmost < 0:
            self._n_leaves = 0
        else:
            # Smallest 2^d strictly greater than rightmost leaf index
            target = 1
            while target <= rightmost:
                target <<= 1
            self._n_leaves = target

    def update_leaf(self, index: int, leaf_node: LeafNode) -> None:
        """Replace leaf metadata and blank direct-path intermediate nodes (RFC ?12.1.2)."""
        node_index = index * 2
        node = self.get_node(node_index)
        node.public_key = leaf_node.encryption_key
        node.leaf_node = leaf_node

        # RFC ?12.1.2: blank all intermediate nodes on the direct path
        for p_idx in tree_math.direct_path(node_index, self.n_leaves):
            p_node = self.get_node(p_idx)
            p_node.public_key = None
            p_node.private_key = None
            p_node.parent_hash = b""

        self._recalculate_hashes_from(node_index)

    def _compute_parent_hash_for_leaf(self, leaf_index: int) -> bytes:
        """Compute parent hash binding of a leaf to current direct-path nodes (RFC 9420 ?7.9)."""
        if self.n_leaves == 0:
            return b""
        leaf_node_index = leaf_index * 2
        # Ensure hashes are current
        self._recalculate_hashes_from(leaf_node_index)

        path = tree_math.direct_path(leaf_node_index, self.n_leaves)
        parent_hash = b""

        # Iterate from root down to the parent of the leaf
        # Path excludes the leaf itself, so we append it for child lookup.
        reversed_path = list(reversed(path))
        path_nodes_down = reversed_path + [leaf_node_index]

        # We process each node P in the path (which corresponds to reversed_path elements)
        # using the next node in path_nodes_down as the child C.

        for i, p_idx in enumerate(reversed_path):
            node = self.get_node(p_idx)
            child_idx = path_nodes_down[i + 1]

            if not node.public_key:
                # If parent is blank, parent_hash passes through?
                # RFC 9420 ?7.9: "If the node at height h is blank, then the parent hash... is the same as the parent hash of the node at height h+1."
                # effectively, we don't hash it, just keep the accumulator?
                # or do we exclude it from the chain?
                # "The parent hash... is defined as..."
                # If node is blank, it has no `encryption_key`.
                # If blank, we just continue with same parent_hash?
                continue

            # Compute ParentHashInput for this node P
            # We need sibling of C
            sibling_idx = tree_math.sibling(child_idx, self.n_leaves)
            sibling_hash = self._compute_original_sibling_tree_hash(
                parent_index=p_idx,
                sibling_index=sibling_idx,
            )

            # ParentHashInput
            phi = serialize_bytes(node.public_key)
            phi += serialize_bytes(parent_hash)
            phi += serialize_bytes(sibling_hash)

            parent_hash = self._crypto_provider.hash(phi)

        return parent_hash

    def _compute_update_path_unmerged_leaves(
        self, child_index: int, excluded_leaf_pubkeys: Optional[Set[bytes]] = None
    ) -> List[int]:
        """Compute the unmerged_leaves for a node in an UpdatePath.
        RFC 9420 ?7.1: the parent node's unmerged_leaves is set to the unmerged_leaves
        of the child node on the direct path, plus the resolution of the copath sibling.
        """
        c_node = self.get_node(child_index)
        s_idx = tree_math.sibling(child_index, self.n_leaves)
        res_s = self.resolve_indices(s_idx, excluded_leaf_pubkeys=excluded_leaf_pubkeys)
        new_unmerged = set(c_node.unmerged_leaves)
        for r_node in res_s:
            n = self.get_node(r_node)
            if n.is_leaf:
                new_unmerged.add(r_node // 2)
            else:
                new_unmerged.update(n.unmerged_leaves)
        return sorted(list(new_unmerged))

    def _compute_parent_hash_of_parent_node(
        self, parent_index: int, copath_sibling_index: int
    ) -> bytes:
        """Compute the parent hash of parent node P with copath child S (RFC 9420 ?7.9).

        Returns hash(ParentHashInput) = H(P.encryption_key || P.parent_hash || original_sibling_tree_hash(S)).
        Used to verify that a descendant node D's parent_hash field equals this value.
        """
        node = self.get_node(parent_index)
        if not node.public_key:
            return node.parent_hash or b""
        sibling_hash = self._compute_original_sibling_tree_hash(parent_index, copath_sibling_index)
        phi = serialize_bytes(node.public_key)
        phi += serialize_bytes(node.parent_hash or b"")
        phi += serialize_bytes(sibling_hash)
        return self._crypto_provider.hash(phi)

    def verify_parent_hash_chains(self) -> None:
        """Verify that every non-blank parent node is parent-hash valid (RFC 9420 ?7.9.2).

        When joining a group, the new member MUST authenticate that each non-blank parent
        node P is parent-hash valid (chainable back to a leaf). Raises CommitValidationError
        if any parent node fails.
        """
        if self.n_leaves == 0:
            return
        root_idx = tree_math.root(self.n_leaves)
        valid_parents: Set[int] = set()

        for leaf_index in range(self.n_leaves):
            leaf_node_index = leaf_index * 2
            node = self.get_node(leaf_node_index)
            if not node.leaf_node or not getattr(node.leaf_node, "parent_hash", None):
                continue
            leaf_ph = getattr(node.leaf_node, "parent_hash", b"")
            if not leaf_ph:
                continue

            current = leaf_node_index
            ph_to_check = leaf_ph

            while current != root_idx:
                # Find the next non-blank parent P
                p_idx = current
                while p_idx != root_idx:
                    try:
                        p_idx = tree_math.parent(p_idx, self.n_leaves)
                    except Exception:
                        break
                    if self.get_node(p_idx).public_key is not None:
                        break
                else:
                    break

                p_node = self.get_node(p_idx)
                if not p_node.public_key:
                    break

                # C is the child of P on the direct path to current (which resolves to current if it's the child)
                l_child = tree_math.left(p_idx)
                r_child = tree_math.right(p_idx, self.n_leaves)
                if current == l_child or self._is_leaf_descendant_of(
                    current // 2
                    if self.get_node(current).is_leaf
                    else self._leaf_indices_under(current).pop(),
                    l_child,
                ):
                    c_idx = l_child
                    s_idx = r_child
                else:
                    c_idx = r_child
                    s_idx = l_child

                expected = self._compute_parent_hash_of_parent_node(p_idx, s_idx)
                if ph_to_check != expected:
                    break

                # RFC 9420 ?7.9.2 third criterion: D in resolution(C)
                res_c = self.resolve_indices(c_idx)
                if current not in res_c:
                    break

                # intersection(P.unmerged_leaves, subtree(C)) == resolution(C) \ {D}
                res_c_leaves = {idx // 2 for idx in res_c if self.get_node(idx).is_leaf}
                leaves_under_c = self._leaf_indices_under(c_idx)
                intersection = set(p_node.unmerged_leaves) & leaves_under_c

                expected_set = res_c_leaves.copy()
                if self.get_node(current).is_leaf:
                    expected_set.discard(current // 2)

                if intersection != expected_set:
                    break

                valid_parents.add(p_idx)

                current = p_idx
                ph_to_check = self.get_node(current).parent_hash or b""
                if not ph_to_check:
                    break

        for idx in range(self.node_width()):
            n = self.get_node(idx)
            if n.is_leaf:
                continue
            if n.public_key and idx not in valid_parents:
                raise CommitValidationError(
                    f"parent node at index {idx} is not parent-hash valid (RFC 9420 ?7.9.2)"
                )

    def _is_leaf_descendant_of(self, leaf_index: int, ancestor_index: int) -> bool:
        """Return True if the given leaf is contained in ancestor_index's subtree."""
        if self.n_leaves == 0:
            return False
        if leaf_index < 0 or leaf_index >= self.n_leaves:
            return False
        current = leaf_index * 2
        if current == ancestor_index:
            return True
        for p in tree_math.direct_path(current, self.n_leaves):
            if p == ancestor_index:
                return True
        return False

    def _snapshot_node(
        self, node_index: int
    ) -> tuple[
        Optional[bytes],
        Optional[bytes],
        Optional[bytes],
        Optional[LeafNode],
        Optional[bytes],
        list[int],
    ]:
        """Capture node fields so temporary hash modifications can be reverted safely."""
        n = self.get_node(node_index)
        return (
            n.public_key,
            n.private_key,
            n.parent_hash,
            n.leaf_node,
            n.hash,
            list(n.unmerged_leaves),
        )

    def _restore_node(
        self,
        node_index: int,
        snap: tuple[
            Optional[bytes],
            Optional[bytes],
            Optional[bytes],
            Optional[LeafNode],
            Optional[bytes],
            list[int],
        ],
    ) -> None:
        """Restore a node snapshot captured by _snapshot_node."""
        n = self.get_node(node_index)
        n.public_key, n.private_key, n.parent_hash, n.leaf_node, n.hash, n.unmerged_leaves = snap

    def _compute_original_sibling_tree_hash(self, parent_index: int, sibling_index: int) -> bytes:
        """Compute RFC 9420 ?7.9 original_sibling_tree_hash for a parent/copath sibling pair."""
        parent_node = self.get_node(parent_index)
        if not parent_node.unmerged_leaves:
            self._hash_node(sibling_index)
            return self.get_node(sibling_index).hash or b""

        leaves_to_blank = set(
            leaf_idx
            for leaf_idx in parent_node.unmerged_leaves
            if self._is_leaf_descendant_of(leaf_idx, sibling_index)
        )
        if not leaves_to_blank:
            self._hash_node(sibling_index)
            return self.get_node(sibling_index).hash or b""

        def _hash_virtual(node_idx: int) -> bytes:
            node = self.get_node(node_idx)
            if node.is_leaf:
                leaf_idx = node_idx // 2
                if leaf_idx in leaves_to_blank:
                    blob = write_uint8(1) + write_uint32(leaf_idx) + write_uint8(0)
                    return self._crypto_provider.hash(blob)
                blob = write_uint8(1) + write_uint32(leaf_idx)
                if node.leaf_node:
                    blob += write_uint8(1) + node.leaf_node.serialize()
                else:
                    blob += write_uint8(0)
                return self._crypto_provider.hash(blob)
            else:
                try:
                    l_hash = _hash_virtual(tree_math.left(node_idx))
                    r_hash = _hash_virtual(tree_math.right(node_idx, self.n_leaves))
                except Exception:
                    l_hash = b""
                    r_hash = b""
                blob = write_uint8(2)
                if node.public_key:
                    blob += write_uint8(1)
                    blob += serialize_bytes(node.public_key)
                    blob += serialize_bytes(node.parent_hash or b"")
                    ul_data = b""
                    for ul in sorted([u for u in node.unmerged_leaves if u not in leaves_to_blank]):
                        ul_data += write_uint32(ul)
                    blob += write_varint(len(ul_data)) + ul_data
                else:
                    blob += write_uint8(0)
                blob += serialize_bytes(l_hash)
                blob += serialize_bytes(r_hash)
                return self._crypto_provider.hash(blob)

        return _hash_virtual(sibling_index)

    def _ensure_hash_bottom_up(self, node_index: int) -> None:
        """Ensure node and all descendants are hashed in bottom-up order (RFC 9420 §7.8)."""
        node = self.get_node(node_index)
        if node.hash is not None:
            return
        if not node.is_leaf:
            self._ensure_hash_bottom_up(tree_math.left(node_index))
            self._ensure_hash_bottom_up(tree_math.right(node_index, self.n_leaves))
        self._hash_node(node_index)

    def _recalculate_hashes_from(self, start_node_index: int):
        """Recompute hashes from the given node up to the root along the direct path."""
        path = tree_math.direct_path(start_node_index, self.n_leaves)
        for node_index in [start_node_index] + path:
            self.get_node(node_index).hash = None
        self._ensure_hash_bottom_up(start_node_index)
        for node_index in path:
            self._ensure_hash_bottom_up(node_index)

    def _hash_node(self, node_index: int):
        """Compute and cache the hash (NodeHash) for a node using RFC 9420 ?7.8 TreeHashInput."""
        node = self.get_node(node_index)
        if node.is_leaf:
            # TreeHashInput: node_type=1 (leaf)
            blob = write_uint8(1)

            # LeafNodeHashInput structure
            # struct {
            #     uint32 leaf_index;
            #     optional<LeafNode> leaf_node;
            # } LeafNodeHashInput;

            leaf_idx = node_index // 2
            blob += write_uint32(leaf_idx)

            if node.leaf_node:
                blob += write_uint8(1)  # present
                blob += node.leaf_node.serialize()
            else:
                blob += write_uint8(0)  # not present

            node.hash = self._crypto_provider.hash(blob)
        else:
            left_child_hash = self.get_node(tree_math.left(node_index)).hash or b""
            right_child_hash = self.get_node(tree_math.right(node_index, self.n_leaves)).hash or b""

            # TreeHashInput: node_type=2 (parent)
            blob = write_uint8(2)

            # ParentNodeHashInput structure
            # struct {
            #     optional<ParentNode> parent_node;
            #     opaque left_hash<V>;
            #     opaque right_hash<V>;
            # } ParentNodeHashInput;

            if node.public_key:
                # ParentNode present
                blob += write_uint8(1)

                # struct {
                #     HPKEPublicKey encryption_key;
                #     opaque parent_hash<V>;
                #     uint32 unmerged_leaves<V>;
                # } ParentNode;

                blob += serialize_bytes(node.public_key)
                blob += serialize_bytes(node.parent_hash or b"")
                # unmerged_leaves<V>
                ul_data = b""
                for ul in sorted(node.unmerged_leaves):
                    ul_data += write_uint32(ul)
                blob += write_varint(len(ul_data)) + ul_data
            else:
                blob += write_uint8(0)  # not present

            blob += serialize_bytes(left_child_hash)
            blob += serialize_bytes(right_child_hash)

            node.hash = self._crypto_provider.hash(blob)

    def calculate_tree_hash(self) -> bytes:
        """Return the current tree hash (hash of the root), or empty if no leaves."""
        if self.n_leaves == 0:
            return b""
        root_index = tree_math.root(self.n_leaves)
        self._ensure_hash_bottom_up(root_index)
        return self.get_node(root_index).hash or b""

    def resolve(
        self, node_index: int, excluded_leaf_pubkeys: Optional[Set[bytes]] = None
    ) -> list[RatchetTreeNode]:
        """
        Return the resolution of a node as defined in RFC 9420 ?4.1.1.
        The resolution is an ordered list of non-blank nodes that cover all non-blank
        descendants of the node.
        """
        node = self.get_node(node_index)
        if node.public_key is not None:
            res = [node]
            for leaf_idx in node.unmerged_leaves:
                leaf_node_idx = leaf_idx * 2
                if leaf_node_idx < self.node_width():
                    res.append(self.get_node(leaf_node_idx))
        elif node.is_leaf:
            res = []
        else:
            try:
                left_res = self.resolve(tree_math.left(node_index), excluded_leaf_pubkeys)
                right_res = self.resolve(
                    tree_math.right(node_index, self.n_leaves), excluded_leaf_pubkeys
                )
                res = left_res + right_res
            except Exception:
                res = []

        if excluded_leaf_pubkeys:
            res = [r for r in res if r.public_key not in excluded_leaf_pubkeys]

        return res

    def resolve_indices(
        self, node_index: int, excluded_leaf_pubkeys: Optional[Set[bytes]] = None
    ) -> list[int]:
        """Return the resolution of a node as a list of node indices (RFC 9420 ?4.1.1)."""
        node = self.get_node(node_index)
        if node.public_key is not None:
            res = [node_index]
            for leaf_idx in node.unmerged_leaves:
                leaf_node_idx = leaf_idx * 2
                if leaf_node_idx < self.node_width():
                    res.append(leaf_node_idx)
        elif node.is_leaf:
            res = []
        else:
            try:
                left_res = self.resolve_indices(tree_math.left(node_index), excluded_leaf_pubkeys)
                right_res = self.resolve_indices(
                    tree_math.right(node_index, self.n_leaves), excluded_leaf_pubkeys
                )
                res = left_res + right_res
            except Exception:
                res = []

        if excluded_leaf_pubkeys:
            res = [idx for idx in res if self.get_node(idx).public_key not in excluded_leaf_pubkeys]

        return res

    def _leaf_indices_under(self, node_index: int) -> Set[int]:
        """Return set of leaf indices that are descendants of the given node."""
        out: Set[int] = set()
        node = self.get_node(node_index)
        if node.is_leaf:
            out.add(node_index // 2)
            return out
        try:
            left_idx = tree_math.left(node_index)
            right_idx = tree_math.right(node_index, self.n_leaves)
            out |= self._leaf_indices_under(left_idx)
            out |= self._leaf_indices_under(right_idx)
        except Exception:
            pass
        return out

    def filtered_direct_path(
        self, node_index: int, excluded_leaf_pubkeys: Optional[Set[bytes]] = None
    ) -> list[int]:
        """
        Return the filtered direct path of a node (RFC 9420 ?4.1.2).
        The filtered direct path is the direct path with nodes removed if their
        child on the copath has an empty resolution.
        """
        d = tree_math.direct_path(node_index, self.n_leaves)
        filtered: list[int] = []
        for p in d:
            if not filtered and p == tree_math.parent(node_index, self.n_leaves):
                c = node_index
            else:
                if d.index(p) == 0:
                    c = node_index
                else:
                    c = d[d.index(p) - 1]

            s = tree_math.sibling(c, self.n_leaves)

            # Check resolution of s
            if self.resolve(s, excluded_leaf_pubkeys=excluded_leaf_pubkeys):
                filtered.append(p)

        return filtered

    def node_width(self) -> int:
        return tree_math.node_width(self.n_leaves)

    def create_update_path(
        self,
        committer_index: int,
        new_leaf_node: LeafNode,
        group_context_bytes: bytes,
        excluded_leaf_pubkeys: Optional[Set[bytes]] = None,
    ) -> tuple[UpdatePath, bytes, dict[int, bytes]]:
        """Create an UpdatePath for the committer and derive the commit secret.

        RFC 9420 ?7.4: Generate a fresh path_secret at the leaf and derive
        subsequent path/node secrets top-down up the direct path. For each
        direct-path node, derive a deterministic key pair from the node_secret.
        Encrypt the path_secret for the copath resolution. Attach a parent hash
        to the new leaf node. Return (UpdatePath, commit_secret), where
        commit_secret is the final path_secret at the root.

        Args:
            excluded_leaf_pubkeys: HPKE public keys of newly added members that
                MUST be excluded from path-secret encryption (RFC ?7.4). These
                members were added in the same commit and cannot decrypt path
                secrets because they don't yet have the tree secrets.
        """
        direct_path = self.filtered_direct_path(
            committer_index * 2, excluded_leaf_pubkeys=excluded_leaf_pubkeys
        )
        full_direct_path = tree_math.direct_path(committer_index * 2, self.n_leaves)
        filtered_set = set(direct_path)

        if not full_direct_path:
            # Single-member tree
            update_path = UpdatePath(new_leaf_node.serialize(), [])
            commit_secret = self._crypto_provider.kdf_extract(b"", b"")
            return update_path, commit_secret, {}

        # RFC ?7.4: path_secret[0] = random; use current, THEN derive next (use-then-derive)
        current_path_secret = os.urandom(self._crypto_provider.kdf_hash_len())

        path_secret_by_node: dict[int, bytes] = {}

        for i, node_index in enumerate(full_direct_path):
            if node_index in filtered_set:
                path_secret_by_node[node_index] = current_path_secret
                node_secret = self._crypto_provider.derive_secret(current_path_secret, b"node")
                priv_key, pub_key = self._crypto_provider.derive_key_pair(node_secret)
                self._nodes[node_index].private_key = priv_key
                self._nodes[node_index].public_key = pub_key
                self._nodes[node_index].unmerged_leaves = []
                # RFC 9420 §7.4: advance path_secret only along filtered direct path
                current_path_secret = self._crypto_provider.derive_secret(
                    current_path_secret, b"path"
                )
            else:
                self._nodes[node_index].private_key = None
                self._nodes[node_index].public_key = None
                self._nodes[node_index].unmerged_leaves = []
                self._nodes[node_index].leaf_node = None

        # RFC 9420 ?12.4.2: provisional GroupContext tree_hash MUST reflect the
        # tree AFTER the sender's direct path update. Recompute it now.
        from .data_structures import GroupContext as _GC

        try:
            gc_obj = _GC.deserialize(group_context_bytes)
            corrected_tree_hash = self.calculate_tree_hash()
            corrected_gc = _GC(
                gc_obj.group_id,
                gc_obj.epoch,
                corrected_tree_hash,
                gc_obj.confirmed_transcript_hash,
                gc_obj.extensions,
                cipher_suite_id=gc_obj.cipher_suite_id,
            )
            group_context_bytes = corrected_gc.serialize()
        except Exception:
            pass

        update_path_nodes: list[UpdatePathNode] = []

        for node_index in direct_path:
            node = self.get_node(node_index)
            if not node.public_key:
                # Should not happen if filtered correctly
                continue
                # raise ValueError(f"Node {node_index} in filtered path but has no public key")

            # Encrypt path secret to resolution of copath node
            try:
                copath_node_index = tree_math.sibling(node_index, self.n_leaves)
            except Exception:
                copath_node_index = None

            encrypted_secrets = []
            if copath_node_index is not None:
                path_secret = path_secret_by_node[node_index]
                resolution_nodes = self.resolve(copath_node_index)

                # RFC ?7.4: exclude newly-added leaves ? they were added in this
                # commit and have no tree secrets to decrypt path secrets.
                if excluded_leaf_pubkeys:
                    resolution_nodes = [
                        rn for rn in resolution_nodes if rn.public_key not in excluded_leaf_pubkeys
                    ]

                for res_node in resolution_nodes:
                    if res_node.public_key:
                        enc, ct = encrypt_with_label(
                            self._crypto_provider,
                            recipient_public_key=res_node.public_key,
                            label=mls_labels.HPKE_UPDATE_PATH_NODE,
                            context=group_context_bytes,
                            aad=b"",
                            plaintext=path_secret,
                        )
                        hpke_ciphertext = write_opaque_varint(enc) + write_opaque_varint(ct)
                        encrypted_secrets.append(hpke_ciphertext)

            update_path_nodes.append(
                UpdatePathNode(
                    encryption_key=node.public_key, encrypted_path_secrets=encrypted_secrets
                )
            )

        parent_hash = self._compute_parent_hash_for_leaf(committer_index)

        # Create leaf with COMMIT source
        leaf_for_path = LeafNode(
            encryption_key=new_leaf_node.encryption_key,
            signature_key=new_leaf_node.signature_key,
            credential=new_leaf_node.credential,
            capabilities=new_leaf_node.capabilities,
            leaf_node_source=LeafNodeSource.COMMIT,
            parent_hash=parent_hash,
            lifetime_not_before=new_leaf_node.lifetime_not_before,
            lifetime_not_after=new_leaf_node.lifetime_not_after,
            extensions=new_leaf_node.extensions,
            signature=new_leaf_node.signature,
        )

        update_path = UpdatePath(leaf_for_path.serialize(), update_path_nodes)
        # RFC 9420 ?7.4: commit_secret = path_secret[n+1] = DeriveSecret(path_secret[n], "path")
        # where n is the last node of the filtered direct path. After the loop,
        # current_path_secret has already been advanced one step past the last
        # filtered node, so it IS the commit_secret.
        commit_secret = current_path_secret
        return update_path, commit_secret, path_secret_by_node

    def merge_update_path(
        self,
        update_path: UpdatePath,
        committer_index: int,
        group_context_bytes: bytes,
        excluded_leaf_pubkeys: Optional[Set[bytes]] = None,
    ) -> bytes:
        """Merge an UpdatePath from a received commit and return the commit secret.

        RFC 9420 ?7.4 receive path:
        - Verify parent hash binding for provided leaf (if present)
        - Decrypt exactly one path_secret corresponding to a copath node on our
          direct path; then derive subsequent path/node secrets upward
        - Update keys along the direct path and recompute hashes

        excluded_leaf_pubkeys: HPKE public keys of new members added in the same
            Commit (RFC 9420 ?7.5). They MUST be excluded from the copath
            resolution when comparing length and when decrypting.
        """
        # Update leaf node
        provided_leaf = LeafNode.deserialize(update_path.leaf_node)
        self.update_leaf(committer_index, provided_leaf)

        # Decrypt a single path_secret for the lowest applicable node; then derive upwards
        # The UpdatePath nodes correspond to the *filtered direct path*.
        # We need to map them to our direct path.

        # RFC 9420 ?7.4:
        # "The receiver... identifies the first node in the filtered direct path... for which it possesses a private key in the resolution of the copath node."

        filtered_path = self.filtered_direct_path(
            committer_index * 2, excluded_leaf_pubkeys=excluded_leaf_pubkeys
        )
        # RFC 9420 ?12.4.2: path encryption keys MUST be unique in the tree.
        try:
            from .validations import validate_update_path_key_uniqueness

            validate_update_path_key_uniqueness(
                self,
                [n.encryption_key for n in update_path.nodes if n.encryption_key],
                committer_index,
            )
        except Exception as e:
            if isinstance(e, CommitValidationError):
                raise
            raise CommitValidationError(f"invalid UpdatePath encryption keys: {e}") from e

        decrypted_index: Optional[int] = None
        current_path_secret: Optional[bytes] = None

        # Iterate over both the filtered path and the UpdatePath nodes
        # They should align.
        if len(update_path.nodes) != len(filtered_path):
            pass

        # Phase 1: Update ALL public keys from UpdatePath before computing tree_hash.
        # RFC 9420 ?12.4.2: merge first, THEN construct provisional GroupContext
        # with the correct tree_hash, THEN decrypt path secrets.
        for i, node_index in enumerate(filtered_path):
            if i >= len(update_path.nodes):
                break

            up_node = update_path.nodes[i]
            nd = self.get_node(node_index)
            nd.public_key = up_node.encryption_key
            nd.unmerged_leaves = []

        # Recompute tree_hash after merging public keys, then rebuild GC bytes
        from .data_structures import GroupContext as _GC

        try:
            gc_obj = _GC.deserialize(group_context_bytes)
            corrected_tree_hash = self.calculate_tree_hash()
            corrected_gc = _GC(
                gc_obj.group_id,
                gc_obj.epoch,
                corrected_tree_hash,
                gc_obj.confirmed_transcript_hash,
                gc_obj.extensions,
                cipher_suite_id=gc_obj.cipher_suite_id,
            )
            group_context_bytes = corrected_gc.serialize()
        except Exception:
            pass

        # Phase 2: Attempt HPKE decryption using the corrected group_context_bytes
        for i, node_index in enumerate(filtered_path):
            if i >= len(update_path.nodes):
                break

            if current_path_secret is not None:
                break

            up_node = update_path.nodes[i]

            if node_index == tree_math.root(self.n_leaves):
                continue

            copath_node_index = tree_math.sibling(node_index, self.n_leaves)
            resolution_filtered = self.resolve(
                copath_node_index, excluded_leaf_pubkeys=excluded_leaf_pubkeys
            )
            if len(up_node.encrypted_path_secrets) != len(resolution_filtered):
                raise CommitValidationError(
                    "UpdatePath node encrypted_path_secret count does not match copath resolution length (RFC 9420 ?7.6)"
                )

            for j, res_node in enumerate(resolution_filtered):
                if res_node.private_key:
                    blob = up_node.encrypted_path_secrets[j]
                    try:
                        from .data_structures import deserialize_bytes

                        kem_out, rest_ct = deserialize_bytes(blob)
                        ct, _ = deserialize_bytes(rest_ct)

                        ps = decrypt_with_label(
                            self._crypto_provider,
                            recipient_private_key=res_node.private_key,
                            kem_output=kem_out,
                            label=mls_labels.HPKE_UPDATE_PATH_NODE,
                            context=group_context_bytes,
                            aad=b"",
                            ciphertext=ct,
                        )
                        decrypted_index = node_index
                        current_path_secret = ps
                        break
                    except Exception:
                        continue

        if current_path_secret is None:
            # RFC 9420 ?7.6: decryption failure MUST cause the commit to be rejected
            raise CommitValidationError(
                "merge_update_path: could not decrypt any path secret from UpdatePath"
            )

        # RFC 9420 ?7.4: derive path/node secrets along the *filtered* direct path
        # only, starting from the decrypted node upward.
        if decrypted_index not in filtered_path:
            raise CommitValidationError("decrypted node not in committer's filtered direct path")
        decrypted_filtered_idx = filtered_path.index(decrypted_index)

        for fi in range(decrypted_filtered_idx, len(filtered_path)):
            node_index = filtered_path[fi]
            if fi > decrypted_filtered_idx:
                current_path_secret = self._crypto_provider.derive_secret(
                    current_path_secret, b"path"
                )

            node_secret = self._crypto_provider.derive_secret(current_path_secret, b"node")
            priv_key, pub_key = self._crypto_provider.derive_key_pair(node_secret)

            if fi < len(update_path.nodes):
                expected_pk = update_path.nodes[fi].encryption_key
                if expected_pk and pub_key != expected_pk:
                    raise CommitValidationError(
                        f"Derived public key at node {node_index} does not match UpdatePath"
                    )

            self.get_node(node_index).private_key = priv_key
            self.get_node(node_index).public_key = pub_key

        self._recalculate_hashes_from(committer_index * 2)

        # Pass 1: Set parent_hash top-down (root to leaf). RFC 9420 §7.10: each node's
        # parent_hash is the hash of its parent's ParentNodeHashInput; parent's
        # parent_hash must be set first.
        root_idx = tree_math.root(self.n_leaves)
        self.get_node(root_idx).parent_hash = b""
        path_top_down = list(reversed(filtered_path))
        for path_node_index in path_top_down:
            if path_node_index == root_idx:
                self.get_node(path_node_index).parent_hash = b""
            else:
                try:
                    parent_idx = tree_math.parent(path_node_index, self.n_leaves)
                    s_idx = tree_math.sibling(path_node_index, self.n_leaves)
                    ph = self._compute_parent_hash_of_parent_node(parent_idx, s_idx)
                    self.get_node(path_node_index).parent_hash = ph if ph else None
                except Exception:
                    continue

        # Pass 2: Invalidate and recompute node hashes so tree_hash reflects new parent_hash values
        for path_node_index in filtered_path + [root_idx]:
            self.get_node(path_node_index).hash = None
        self._ensure_hash_bottom_up(root_idx)

        try:
            if provided_leaf.parent_hash:
                expected_after = self._compute_parent_hash_for_leaf(committer_index)
                if expected_after != provided_leaf.parent_hash:
                    raise CommitValidationError("parent_hash mismatch after applying update path")
        except Exception:
            raise CommitValidationError("parent_hash validation failed")

        commit_secret = self._crypto_provider.derive_secret(current_path_secret, b"path")
        return commit_secret

    def merge_update_path_public_only(self, update_path: UpdatePath, committer_index: int) -> None:
        """Merge an UpdatePath using only public data (no decryption).
        Per RFC 9420 §7.5 ordering:
        - Compute filtered direct path from current tree
        - Blank sender direct path
        - Set filtered direct-path public keys from UpdatePath and clear unmerged lists
        - Recompute parent hashes top-down and tree hash bottom-up
        Used for test-vector verification."""
        leaf_node_index = committer_index * 2
        filtered_path = self.filtered_direct_path(leaf_node_index)
        full_direct_path = tree_math.direct_path(leaf_node_index, self.n_leaves)

        # RFC 9420 §7.5: blank all direct-path nodes before merge.
        for node_index in full_direct_path:
            nd = self.get_node(node_index)
            nd.public_key = None
            nd.private_key = None
            nd.parent_hash = None
            nd.unmerged_leaves = []
            nd.hash = None

        # Update sender leaf from UpdatePath.
        provided_leaf = LeafNode.deserialize(update_path.leaf_node)
        self.update_leaf(committer_index, provided_leaf)

        for i, node_index in enumerate(filtered_path):
            if i >= len(update_path.nodes):
                break
            up_node = update_path.nodes[i]
            nd = self.get_node(node_index)
            nd.public_key = up_node.encryption_key
            nd.unmerged_leaves = []

        self._recalculate_hashes_from(committer_index * 2)

        root_idx = tree_math.root(self.n_leaves)
        self.get_node(root_idx).parent_hash = b""
        path_top_down = list(reversed(filtered_path))
        for path_node_index in path_top_down:
            if path_node_index == root_idx:
                self.get_node(path_node_index).parent_hash = b""
            else:
                try:
                    parent_idx = tree_math.parent(path_node_index, self.n_leaves)
                    s_idx = tree_math.sibling(path_node_index, self.n_leaves)
                    ph = self._compute_parent_hash_of_parent_node(parent_idx, s_idx)
                    self.get_node(path_node_index).parent_hash = ph if ph else None
                except Exception:
                    continue

        for path_node_index in filtered_path + [root_idx]:
            self.get_node(path_node_index).hash = None
        self._ensure_hash_bottom_up(root_idx)

    def apply_joiner_path_secret(
        self,
        joiner_leaf_index: int,
        path_secret_at_lca: bytes,
        committer_leaf_index: int = -1,
    ) -> None:
        """Apply path_secret from GroupSecrets when joining via Welcome (RFC 9420 ?12.4.3.1).

        The path_secret is for the LCA of committer and joiner on the committer's
        filtered direct path. Derives path/node secrets upward along the committer's
        filtered direct path from the LCA to the root.
        """
        if committer_leaf_index < 0:
            committer_leaf_index = joiner_leaf_index

        committer_filtered = self.filtered_direct_path(committer_leaf_index * 2)
        lca_node = tree_math.lca(committer_leaf_index * 2, joiner_leaf_index * 2, self.n_leaves)

        if lca_node in committer_filtered:
            lca_idx = committer_filtered.index(lca_node)
        else:
            lca_idx = 0

        current = path_secret_at_lca
        for node_index in committer_filtered[lca_idx:]:
            node_secret = self._crypto_provider.derive_secret(current, b"node")
            priv_key, pub_key = self._crypto_provider.derive_key_pair(node_secret)
            self.get_node(node_index).private_key = priv_key
            current = self._crypto_provider.derive_secret(current, b"path")
        self._recalculate_hashes_from(joiner_leaf_index * 2)

    # --- Welcome ratchet_tree extension helpers ---
    def serialize_tree_for_welcome(self) -> bytes:
        """
        Serialize leaves needed for a new member to reconstruct the tree view.
        Format:
          uint16 n_leaves
          repeated opaque16 leaf_node (empty for blank leaves)
        """
        out = write_uint16(self.n_leaves)
        for leaf in range(self.n_leaves):
            node = self.get_node(leaf * 2)
            if node.leaf_node:
                out += write_opaque16(node.leaf_node.serialize())
            else:
                out += write_opaque16(b"")
        return out

    def serialize_full_tree_for_welcome(self) -> bytes:
        """
        Serialize the ratchet tree per RFC 9420 ?12.4.3.1: optional<Node> ratchet_tree<V>.

        Nodes are in array order (left-to-right in-order). Blank nodes after the
        last non-blank node are omitted per RFC. Each optional<Node> is encoded
        as varint(0) for blank or varint(1) + Node (NodeType + LeafNode or ParentNode).
        """
        width = tree_math.node_width(self.n_leaves)
        # Find last non-blank index (RFC: sender MUST NOT include blank after last non-blank)
        last_non_blank = -1
        for idx in range(width):
            node = self.get_node(idx)
            if node.is_leaf:
                if node.leaf_node is not None:
                    last_non_blank = idx
            else:
                if node.public_key or node.parent_hash:
                    last_non_blank = idx
        if last_non_blank < 0:
            return write_varint(0)  # empty vector
        content = b""
        for idx in range(last_non_blank + 1):
            node = self.get_node(idx)
            if node.is_leaf:
                if node.leaf_node:
                    # optional present: uint8(1) + Node(leaf(1) + LeafNode)
                    content += write_uint8(1)
                    content += write_uint8(1)  # NodeType.leaf
                    content += node.leaf_node.serialize()
                else:
                    content += write_uint8(0)
            else:
                if node.public_key or node.parent_hash:
                    content += write_uint8(1)
                    content += write_uint8(2)  # NodeType.parent
                    # ParentNode: encryption_key, parent_hash, unmerged_leaves<V>
                    content += serialize_bytes(node.public_key or b"")
                    content += serialize_bytes(node.parent_hash or b"")
                    ul_data = b"".join(write_uint32(ul) for ul in sorted(node.unmerged_leaves))
                    content += write_varint(len(ul_data)) + ul_data
                else:
                    content += write_uint8(0)
        return write_varint(len(content)) + content

    def load_tree_from_welcome_bytes(self, data: bytes) -> None:
        """
        Load leaves from a ratchet_tree extension as serialized by serialize_tree_for_welcome().
        """
        off = 0
        n, off = read_uint16(data, off)
        self._n_leaves = 0
        self._nodes.clear()
        for i in range(n):
            blob, off = read_opaque16(data, off)
            if blob:
                leaf = LeafNode.deserialize(blob)
                self.add_leaf(
                    KeyPackage(leaf_node=leaf, signature=Signature(b""))
                )  # signature not validated here
            else:
                # Even if blank, we need to advance the leaf count
                self._n_leaves += 1
        # Re-hash tree
        if self.n_leaves > 0:
            self._recalculate_hashes_from(0)

    def load_full_tree_from_welcome_bytes(self, data: bytes) -> None:
        """
        Load the tree from RFC 9420 ?12.4.3.1 optional<Node> ratchet_tree<V>.

        The receiver extends with blank nodes until length is 2^(d+1)-1, then
        infers n_leaves = 2^d.
        """
        from ..codec.tls import TLSDecodeError

        off = 0
        total_len, off = read_varint(data, off)
        if total_len == 0:
            self._n_leaves = 0
            self._nodes.clear()
            return
        end = off + total_len
        if end > len(data):
            raise TLSDecodeError("ratchet_tree extension shorter than declared length")
        # (node_type, payload): payload is bytes for leaf (1), (pk, ph, unmerged_leaves) for parent (2)
        entries: list[Optional[tuple[int, Any]]] = []
        while off < end:
            opt_len, off = read_uint8(data, off)
            if opt_len == 0:
                entries.append(None)
                continue
            if opt_len != 1:
                raise TLSDecodeError("optional<Node> must have length 0 or 1")
            node_type, off = read_uint8(data, off)
            if node_type == 1:  # leaf
                from .key_packages import LeafNode

                leaf_node, consumed = LeafNode.deserialize_partial(data[off:])
                off += consumed
                entries.append((1, leaf_node))
            elif node_type == 2:  # parent: encryption_key, parent_hash, unmerged_leaves<V>
                pk, off = read_opaque_varint(data, off)
                ph, off = read_opaque_varint(data, off)
                ul_len, off = read_varint(data, off)
                unmerged_leaves = []
                ul_end = off + ul_len
                if ul_end > len(data):
                    raise TLSDecodeError("unmerged_leaves<V> extends past ratchet_tree buffer")
                if ul_len % 4 != 0:
                    raise TLSDecodeError(
                        "unmerged_leaves<V> length must be a multiple of 4 (uint32)"
                    )
                while off < ul_end:
                    ul_val, off = read_uint32(data, off)
                    unmerged_leaves.append(ul_val)
                entries.append((2, (pk, ph, unmerged_leaves)))
            else:
                raise TLSDecodeError(f"invalid NodeType {node_type}")
        # RFC: extend with blank until length = 2^(d+1)-1
        n_entries = len(entries)
        if n_entries == 0:
            self._n_leaves = 0
            self._nodes.clear()
            return
        # Minimum width = 2^(d+1)-1 >= n_entries => d = ceil(log2(n_entries+1)) - 1
        d = 0
        while (1 << (d + 1)) - 1 < n_entries:
            d += 1
        width = (1 << (d + 1)) - 1
        n_leaves = 1 << d
        self._n_leaves = n_leaves
        self._nodes.clear()
        for i in range(width):
            self._nodes[i] = RatchetTreeNode(is_leaf=(i % 2 == 0))
        # Fill from entries (entries may be shorter; rest are blank)
        off = 0
        for idx in range(width):
            if idx >= len(entries):
                continue
            ent = entries[idx]
            if ent is None:
                continue
            node_type, payload = ent
            node = self.get_node(idx)
            if node_type == 1:
                leaf: LeafNode = payload
                node.public_key = leaf.encryption_key
                node.leaf_node = leaf
            else:
                pk, ph, unmerged_leaves = cast(tuple[Any, Any, Any], payload)
                node.public_key = pk if pk else None
                node.parent_hash = ph if ph else None
                node.unmerged_leaves = list(unmerged_leaves) if unmerged_leaves else []
        if self.n_leaves > 0:
            root_idx = tree_math.root(self.n_leaves)
            self._ensure_hash_bottom_up(root_idx)

    # --- Persistence helpers (full state, including private keys when present) ---
    def serialize_full_state(self) -> bytes:
        """
        Serialize the full ratchet tree state, including private keys where present.
        Format:
          uint16 n_leaves
          uint16 node_count
          repeated {
            uint8 node_type (0=blank, 1=leaf, 2=parent)
            if leaf:
              opaque16 leaf_node (may be empty)
              opaque16 public_key (may be empty)
              opaque16 private_key (may be empty)
            if parent:
              opaque16 public_key (may be empty)
              opaque16 private_key (may be empty)
              opaque16 parent_hash (may be empty)
          }
        """
        out = write_uint16(self.n_leaves)
        width = tree_math.node_width(self.n_leaves)
        out += write_uint16(width)
        for idx in range(width):
            node = self.get_node(idx)
            if node.is_leaf:
                if node.leaf_node or node.public_key or node.private_key:
                    out += write_uint8(1)
                    out += write_opaque16(node.leaf_node.serialize() if node.leaf_node else b"")
                    out += write_opaque16(node.public_key or b"")
                    out += write_opaque16(node.private_key or b"")
                else:
                    out += write_uint8(0)
            else:
                if node.public_key or node.private_key or node.parent_hash:
                    out += write_uint8(2)
                    out += write_opaque16(node.public_key or b"")
                    out += write_opaque16(node.private_key or b"")
                    out += write_opaque16(node.parent_hash or b"")
                else:
                    out += write_uint8(0)
        return out

    def load_full_state(self, data: bytes) -> None:
        """
        Load a full ratchet tree state produced by serialize_full_state().
        """
        off = 0
        n, off = read_uint16(data, off)
        width, off = read_uint16(data, off)
        self._n_leaves = 0
        self._nodes.clear()
        for _ in range(n):
            self._n_leaves += 1
        for idx in range(width):
            node_type, off = read_uint8(data, off)
            if node_type == 0:
                continue
            node = self.get_node(idx)
            if node.is_leaf:
                blob, off = read_opaque16(data, off)
                pk, off = read_opaque16(data, off)
                sk, off = read_opaque16(data, off)
                if blob:
                    leaf = LeafNode.deserialize(blob)
                    node.leaf_node = leaf
                    node.public_key = leaf.encryption_key
                else:
                    node.public_key = pk if pk else None
                node.private_key = sk if sk else None
            else:
                pk, off = read_opaque16(data, off)
                sk, off = read_opaque16(data, off)
                ph, off = read_opaque16(data, off)
                node.public_key = pk if pk else None
                node.private_key = sk if sk else None
                node.parent_hash = ph if ph else None
        if self.n_leaves > 0:
            self._recalculate_hashes_from(0)

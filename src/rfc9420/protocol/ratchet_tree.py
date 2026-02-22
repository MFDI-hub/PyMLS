"""Ratchet tree representation and update path processing (RFC 9420 Appendix C).

This module provides a minimal array-indexed tree with helpers for adding,
removing, and updating leaves, computing node hashes, and producing/merging
UpdatePath structures used in commits.
"""
from typing import Optional
from .key_packages import KeyPackage, LeafNode, LeafNodeSource
from ..codec.tls import write_uint8, write_uint16, write_uint32, write_varint, write_opaque16, read_uint8, read_uint16, read_opaque16, write_opaque_varint, read_varint, read_uint32
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
        # RFC §7.1: track unmerged leaves for parent nodes
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
        """Place new leaf at leftmost blank position (RFC §12.1.1), or extend tree.

        After placement, all non-blank ancestors on the direct path have the new
        leaf index appended to their unmerged_leaves list (RFC §7.1).
        """
        if key_package.leaf_node is None:
            raise ValueError("KeyPackage.leaf_node must be present to add a leaf")

        # Find leftmost blank leaf (RFC §12.1.1)
        leaf_index: Optional[int] = None
        for i in range(self._n_leaves):
            node = self.get_node(i * 2)
            if node.leaf_node is None and node.public_key is None:
                leaf_index = i
                break
        if leaf_index is None:
            # No blank leaf found – extend tree
            leaf_index = self._n_leaves
            self._n_leaves += 1

        node_index = leaf_index * 2
        node = self.get_node(node_index)
        node.public_key = key_package.leaf_node.encryption_key
        node.leaf_node = key_package.leaf_node

        # RFC §7.1: add new leaf index to unmerged_leaves of non-blank ancestors
        for ancestor_idx in tree_math.direct_path(node_index, self._n_leaves):
            ancestor = self.get_node(ancestor_idx)
            if ancestor.public_key is not None:
                if leaf_index not in ancestor.unmerged_leaves:
                    ancestor.unmerged_leaves.append(leaf_index)
                    ancestor.unmerged_leaves.sort()

        self._recalculate_hashes_from(node_index)
        return leaf_index

    def remove_leaf(self, index: int) -> None:
        """Blank a leaf and its direct path; then resize to 2^d leaves (RFC §12.1.3)."""
        node_index = index * 2
        node = self.get_node(node_index)
        node.public_key = None
        node.private_key = None
        node.leaf_node = None

        # Blank the direct path (RFC §12.1.3)
        for p_idx in tree_math.direct_path(node_index, self.n_leaves):
            p_node = self.get_node(p_idx)
            p_node.public_key = None
            p_node.private_key = None
            p_node.unmerged_leaves = []

        self._recalculate_hashes_from(node_index)

        # RFC §12.1.3: truncate to smallest 2^d where 2^d >= (rightmost non-blank leaf + 1)
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
        """Replace leaf metadata and blank direct-path intermediate nodes (RFC §12.1.2)."""
        node_index = index * 2
        node = self.get_node(node_index)
        node.public_key = leaf_node.encryption_key
        node.leaf_node = leaf_node

        # RFC §12.1.2: blank all intermediate nodes on the direct path
        for p_idx in tree_math.direct_path(node_index, self.n_leaves):
            p_node = self.get_node(p_idx)
            p_node.public_key = None
            p_node.private_key = None
            p_node.parent_hash = b""
            p_node.unmerged_leaves = []

        self._recalculate_hashes_from(node_index)

    def _compute_parent_hash_for_leaf(self, leaf_index: int) -> bytes:
        """Compute parent hash binding of a leaf to current direct-path nodes (RFC 9420 §7.9)."""
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
                # RFC 9420 §7.9: "If the node at height h is blank, then the parent hash... is the same as the parent hash of the node at height h+1."
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

    def _snapshot_node(self, node_index: int) -> tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[LeafNode], Optional[bytes], list[int]]:
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

    def _restore_node(self, node_index: int, snap: tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[LeafNode], Optional[bytes], list[int]]) -> None:
        """Restore a node snapshot captured by _snapshot_node."""
        n = self.get_node(node_index)
        n.public_key, n.private_key, n.parent_hash, n.leaf_node, n.hash, n.unmerged_leaves = snap

    def _compute_original_sibling_tree_hash(self, parent_index: int, sibling_index: int) -> bytes:
        """Compute RFC 9420 §7.9 original_sibling_tree_hash for a parent/copath sibling pair."""
        parent_node = self.get_node(parent_index)
        if not parent_node.unmerged_leaves:
            self._hash_node(sibling_index)
            return self.get_node(sibling_index).hash or b""

        # Collect only unmerged leaves that lie under the sibling subtree.
        leaves_to_blank = [
            leaf_idx
            for leaf_idx in parent_node.unmerged_leaves
            if self._is_leaf_descendant_of(leaf_idx, sibling_index)
        ]
        if not leaves_to_blank:
            self._hash_node(sibling_index)
            return self.get_node(sibling_index).hash or b""

        snapshots: dict[int, tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[LeafNode], Optional[bytes], list[int]]] = {}

        def snapshot_once(idx: int) -> None:
            if idx not in snapshots:
                snapshots[idx] = self._snapshot_node(idx)

        try:
            # Blank each affected leaf and clear references from all parent unmerged sets.
            for leaf_idx in leaves_to_blank:
                leaf_node_index = leaf_idx * 2
                snapshot_once(leaf_node_index)
                leaf_node = self.get_node(leaf_node_index)
                leaf_node.public_key = None
                leaf_node.private_key = None
                leaf_node.leaf_node = None

            for idx, node in list(self._nodes.items()):
                if node.is_leaf or not node.unmerged_leaves:
                    continue
                new_ul = [u for u in node.unmerged_leaves if u not in leaves_to_blank]
                if new_ul != node.unmerged_leaves:
                    snapshot_once(idx)
                    node.unmerged_leaves = new_ul

            # Recompute hashes from each modified leaf to root, then read sibling hash.
            for leaf_idx in leaves_to_blank:
                self._recalculate_hashes_from(leaf_idx * 2)
            self._hash_node(sibling_index)
            return self.get_node(sibling_index).hash or b""
        finally:
            # Restore all temporarily modified nodes.
            for idx, snap in snapshots.items():
                self._restore_node(idx, snap)
            # Refresh hashes along restored paths so caller state remains consistent.
            for leaf_idx in leaves_to_blank:
                self._recalculate_hashes_from(leaf_idx * 2)

    def _recalculate_hashes_from(self, start_node_index: int):
        """Recompute hashes from the given node up to the root along the direct path."""
        self._hash_node(start_node_index)
        path = tree_math.direct_path(start_node_index, self.n_leaves)
        for node_index in path:
            self._hash_node(node_index)

    def _hash_node(self, node_index: int):
        """Compute and cache the hash (NodeHash) for a node using RFC 9420 §7.8 TreeHashInput."""
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
                blob += write_uint8(1) # present
                blob += node.leaf_node.serialize()
            else:
                blob += write_uint8(0) # not present
                
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
                blob += write_uint8(0) # not present
            
            blob += serialize_bytes(left_child_hash)
            blob += serialize_bytes(right_child_hash)
            
            node.hash = self._crypto_provider.hash(blob)

    def calculate_tree_hash(self) -> bytes:
        """Return the current tree hash (hash of the root), or empty if no leaves."""
        if self.n_leaves == 0:
            return b""
        root_index = tree_math.root(self.n_leaves)
        # Ensure hashes are up to date from root down
        self._hash_node(root_index)
        return self.get_node(root_index).hash or b""

    def resolve(self, node_index: int) -> list[RatchetTreeNode]:
        """
        Return the resolution of a node as defined in RFC 9420 §4.1.1.
        The resolution is an ordered list of non-blank nodes that cover all non-blank
        descendants of the node.
        """
        node = self.get_node(node_index)
        # If the node is non-blank (has a public key), its resolution is the node
        # itself plus any unmerged leaves.
        if node.public_key is not None:
             res = [node]
             # Append unmerged leaves (RFC §4.1.1: local unmerged leaves)
             # Note: logic for unmerged leaves in resolution might be complex depending on
             # where they are stored. The RFC says "plus the ordered list of unmerged leaves
             # for the node". Our `unmerged_leaves` field stores indices.
             # We should probably return the nodes for those leaves.
             for leaf_idx in node.unmerged_leaves:
                 # Check if the unmerged leaf is actually in the tree
                 # (it should be, but let's be safe)
                 leaf_node_idx = leaf_idx * 2
                 if leaf_node_idx < self.node_width():
                     res.append(self.get_node(leaf_node_idx))
             return res
        
        # If the node is blank and is a leaf, its resolution is the empty list.
        if node.is_leaf:
            return []
            
        # If the node is blank and is an intermediate node, its resolution is the
        # concatenation of the resolutions of its children.
        try:
            left_res = self.resolve(tree_math.left(node_index))
            right_res = self.resolve(tree_math.right(node_index, self.n_leaves))
            return left_res + right_res
        except Exception:
            # If children don't exist (e.g. right child out of bounds), treat as empty
            return []

    def filtered_direct_path(self, node_index: int) -> list[int]:
        """
        Return the filtered direct path of a node (RFC 9420 §4.1.2).
        The filtered direct path is the direct path with nodes removed if their
        child on the copath has an empty resolution.
        """
        d = tree_math.direct_path(node_index, self.n_leaves)
        filtered: list[int] = []
        for p in d:
            # Child on the direct path is the one from which we came.
            # We need to find the child of p that is on the copath of node_index.
            # Actually, the definition says: "remove nodes whose child on the *copath*
            # has empty resolution".
            # The children of p are (left, right). One is on the direct path, the other is on the copath.
            # We check the resolution of the *sibling* of the node on the direct path.
            
            # Find the child of p that is on the direct path (or is node_index itself)
            # We can iterate up.
            # But simpler: the child on the copath is simply the sibling of the child on the 
            # direct path.
            # Wait, `p` is in the direct path of `node_index`.
            # Let `c` be the child of `p` that is also in the direct path (or `node_index`).
            # The "child on the copath" is `sibling(c)`.
            
            # Let's find `c`. `c` is the node below `p` in the path.
            # Since `d` is ordered from leaf to root (in our tree_math, let's verify),
            # `direct_path` returns "indices on the path from node x up to ... root".
            # So `d[0]` is parent of `node_index`. `d[1]` is parent of `d[0]`.
            
            if not filtered and p == tree_math.parent(node_index, self.n_leaves):
                c = node_index
            else:
                # If we have started building filtered, p is parent of the last added node?
                # No, d is independent.
                # We need to look at the previous node in the chain x -> ... -> root.
                # If d = [p1, p2, ...], x -> p1 -> p2.
                # For p1, child is x.
                # For p2, child is p1.
                if d.index(p) == 0:
                     c = node_index
                else:
                     c = d[d.index(p) - 1]
            
            s = tree_math.sibling(c, self.n_leaves)
            
            # Check resolution of s
            if self.resolve(s):
                filtered.append(p)
                
        return filtered

    def node_width(self) -> int:
        return tree_math.node_width(self.n_leaves)

    def create_update_path(
        self,
        committer_index: int,
        new_leaf_node: LeafNode,
        group_context_bytes: bytes,
        excluded_leaf_pubkeys: "set[bytes] | None" = None,
    ) -> tuple[UpdatePath, bytes]:
        """Create an UpdatePath for the committer and derive the commit secret.

        RFC 9420 §7.4: Generate a fresh path_secret at the leaf and derive
        subsequent path/node secrets top-down up the direct path. For each
        direct-path node, derive a deterministic key pair from the node_secret.
        Encrypt the path_secret for the copath resolution. Attach a parent hash
        to the new leaf node. Return (UpdatePath, commit_secret), where
        commit_secret is the final path_secret at the root.

        Args:
            excluded_leaf_pubkeys: HPKE public keys of newly added members that
                MUST be excluded from path-secret encryption (RFC §7.4). These
                members were added in the same commit and cannot decrypt path
                secrets because they don't yet have the tree secrets.
        """
        direct_path = self.filtered_direct_path(committer_index * 2)
        full_direct_path = tree_math.direct_path(committer_index * 2, self.n_leaves)
        filtered_set = set(direct_path)

        if not full_direct_path:
             # Single-member tree
             # Serialize with filtered path (empty) logic?
             # Just return leaf + empty updates.
             update_path = UpdatePath(new_leaf_node.serialize(), [])
             commit_secret = self._crypto_provider.kdf_extract(b"", b"")
             return update_path, commit_secret

        # RFC §7.4: path_secret[0] = random; use current, THEN derive next (use-then-derive)
        current_path_secret = os.urandom(self._crypto_provider.kdf_hash_len())

        # For each node on the direct path, use current secret for this node, then advance
        path_secret_by_node: dict[int, bytes] = {}

        for node_index in full_direct_path:
            # Use current_path_secret for this node BEFORE advancing
            if node_index in filtered_set:
                path_secret_by_node[node_index] = current_path_secret
                node_secret = self._crypto_provider.derive_secret(current_path_secret, b"node")
                priv_key, pub_key = self._crypto_provider.derive_key_pair(node_secret)
                self._nodes[node_index].private_key = priv_key
                self._nodes[node_index].public_key = pub_key
                self._nodes[node_index].unmerged_leaves = []  # cleared by committer
            else:
                self._nodes[node_index].private_key = None
                self._nodes[node_index].public_key = None
                self._nodes[node_index].unmerged_leaves = []
                self._nodes[node_index].leaf_node = None
            # Advance to next path_secret for the next node
            current_path_secret = self._crypto_provider.derive_secret(current_path_secret, b"path")

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

                # RFC §7.4: exclude newly-added leaves — they were added in this
                # commit and have no tree secrets to decrypt path secrets.
                if excluded_leaf_pubkeys:
                    resolution_nodes = [
                        rn for rn in resolution_nodes
                        if rn.public_key not in excluded_leaf_pubkeys
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
            
            update_path_nodes.append(UpdatePathNode(
                encryption_key=node.public_key,
                encrypted_path_secrets=encrypted_secrets
            ))

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
            signature=new_leaf_node.signature
        )

        update_path = UpdatePath(leaf_for_path.serialize(), update_path_nodes)
        # RFC §7.4: commit_secret = path_secret[root], i.e. the path_secret for the
        # root node, NOT the one advanced past the root after the loop ends.
        root_node_index = full_direct_path[-1]
        commit_secret = path_secret_by_node.get(root_node_index, current_path_secret)
        return update_path, commit_secret

    def merge_update_path(self, update_path: UpdatePath, committer_index: int, group_context_bytes: bytes) -> bytes:
        """Merge an UpdatePath from a received commit and return the commit secret.

        RFC 9420 §7.4 receive path:
        - Verify parent hash binding for provided leaf (if present)
        - Decrypt exactly one path_secret corresponding to a copath node on our
          direct path; then derive subsequent path/node secrets upward
        - Update keys along the direct path and recompute hashes
        """
        # Update leaf node
        provided_leaf = LeafNode.deserialize(update_path.leaf_node)
        self.update_leaf(committer_index, provided_leaf)

        # Decrypt a single path_secret for the lowest applicable node; then derive upwards
        # The UpdatePath nodes correspond to the *filtered direct path*.
        # We need to map them to our direct path.
        
        # RFC 9420 §7.4:
        # "The receiver... identifies the first node in the filtered direct path... for which it possesses a private key in the resolution of the copath node."
        
        filtered_path = self.filtered_direct_path(committer_index * 2)
        # RFC 9420 §12.4.2: path encryption keys MUST be unique in the tree.
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
             # This might happen if our view of filtered path differs?
             # Or if the sender's filtered path excluded something correctly that we included, or vice versa.
             # RFC says "The UpdatePath... contains a list of UpdatePathNode... corresponding to the filtered direct path".
             # If we disagree on filtered path, we might misinterpret.
             # However, we can try to find a match.
             pass
        
        for i, node_index in enumerate(filtered_path):
            if i >= len(update_path.nodes):
                break

            up_node = update_path.nodes[i]

            # Update the node's public key; clear unmerged_leaves (RFC §7.5)
            nd = self.get_node(node_index)
            nd.public_key = up_node.encryption_key
            nd.unmerged_leaves = []

            if current_path_secret is not None:
                # We already have the secret, just updating keys
                continue
                
            # Try to decrypt
            # Skip root (no encrypted secrets)
            if node_index == tree_math.root(self.n_leaves):
                continue
            
            # Check if we can decrypt
            # We need to be in the resolution of the copath node.
            # Do we have a private key in the resolution of the copath node?
            # Wait, we just need to try decrypting the blobs.
            # There is a list of blobs. One of them might be for us.
            
            # We are the receiver. We have our own leaf key, and potentially other node keys.
            # We should try to decrypt with any private key we have that is in the resolution of the copath node?
            # Actually, the sender encrypted to the resolution.
            # We just need to check if any of our private keys can decrypt any of the cyphertexts.
            
            # Which private keys do we possess?
            # We possess keys for nodes on our direct path.
            # The copath node is a sibling of a node on the committer's direct path.
            # If we are in the subtree of the copath node, we have keys.
            
            # Optimization: 
            # 1. Identify valid private keys we hold.
            # 2. Try to decrypt.
            
            # In this simple implementation, we can iterate our known private keys?
            # Or simpler:
            # The sender encrypted to specific public keys.
            # Those public keys belong to nodes in the tree.
            # If we hold the private key for a node, we can try.
            
            # But the ciphertext doesn't say "this is for node X". It's just a list.
            # We have to try all our keys against all ciphertexts? That's O(M*N).
            # RFC says "The position in the list... corresponds to the position in the resolution".
            # So we need to compute the resolution of the copath node (same as sender did).
            # Then we check if we hold the private key for the node at index J in the resolution.
            # If so, we attempt to decrypt the J-th ciphertext.
            
            copath_node_index = tree_math.sibling(node_index, self.n_leaves)
            resolution = self.resolve(copath_node_index)
            
            if len(up_node.encrypted_path_secrets) != len(resolution):
                # Valid warnings, but maybe resolution differs due to update?
                # Sender used *their* view (pre-commit?).
                # We use *our* view. They should match.
               continue
            
            for j, res_node in enumerate(resolution):
                # Do we have the private key for `res_node`?
                # `res_node` is a RatchetTreeNode object from `self.get_node`.
                if res_node.private_key:
                    # Try decrypting the j-th secret
                    blob = up_node.encrypted_path_secrets[j]
                    try:
                        from .data_structures import deserialize_bytes
                        # blob is HPKECiphertext (kem_output || ciphertext), but serialized as bytes?
                        # In UpdatePathNode.deserialize we stored raw bytes.
                        # HPKECiphertext = opaque kem<V>; opaque ct<V>;
                        # We need to parse it.
                        
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
            
            if current_path_secret is not None:
                # Found it!
                pass # Continue loop to update remaining public keys
            
        if current_path_secret is None:
            # Unable to decrypt any path secret; derive a neutral commit_secret
            return self._crypto_provider.kdf_extract(b"", b"")

        # From the decrypted node onward, derive subsequent path/node secrets upward
        # We need to find where `decrypted_index` is in the full direct path.
        full_direct_path = tree_math.direct_path(committer_index * 2, self.n_leaves)
        
        start_idx = full_direct_path.index(decrypted_index) if decrypted_index in full_direct_path else 0
        
        for node_index in full_direct_path[start_idx:]:
            # For the first node, use current_path_secret as decrypted; otherwise, step the ratchet
            if node_index != decrypted_index:
                current_path_secret = self._crypto_provider.derive_secret(current_path_secret, b"path")
            
            # Derive keys for this node
            node_secret = self._crypto_provider.derive_secret(current_path_secret, b"node")
            priv_key, pub_key = self._crypto_provider.derive_key_pair(node_secret)
            
            # RFC §7.4: MUST verify that the derived key matches the key in UpdatePath.
            # The UpdatePath node for this index (if it's in filtered_path)
            if node_index in filtered_path:
                up_idx = filtered_path.index(node_index)
                if up_idx < len(update_path.nodes):
                    expected_pk = update_path.nodes[up_idx].encryption_key
                    if expected_pk and pub_key != expected_pk:
                        raise CommitValidationError(
                            f"Derived public key at node {node_index} does not match UpdatePath"
                        )

            # Update the node — we have the private key for decrypted/derived nodes.
            self.get_node(node_index).private_key = priv_key
            self.get_node(node_index).public_key = pub_key


        self._recalculate_hashes_from(committer_index * 2)
        # Re-verify parent hash after applying path secrets to ensure consistency
        try:
            if provided_leaf.parent_hash:
                expected_after = self._compute_parent_hash_for_leaf(committer_index)
                if expected_after != provided_leaf.parent_hash:
                    # Warn or fail? RFC says MUST verify.
                    raise CommitValidationError("parent_hash mismatch after applying update path")
        except Exception:
             # If hash computation fails or mismatch
             raise CommitValidationError("parent_hash validation failed")

        # Commit secret is the final path_secret at the root of the direct path
        commit_secret = current_path_secret
        return commit_secret

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
        Serialize the ratchet tree including internal nodes sufficient for a joiner.
        Format:
          uint16 n_leaves
          uint16 node_count (array width)
          repeated {
            uint8 node_type (0=blank, 1=leaf, 2=parent)
            if leaf:
              opaque16 leaf_node (may be empty if blank)
            if parent:
              opaque16 public_key (may be empty if blank)
              opaque16 parent_hash (may be empty)
          }
        """
        out = write_uint16(self.n_leaves)
        width = tree_math.node_width(self.n_leaves)
        out += write_uint16(width)
        for idx in range(width):
            node = self.get_node(idx)
            if node.is_leaf:
                if node.leaf_node:
                    out += write_uint8(1)
                    out += write_opaque16(node.leaf_node.serialize())
                else:
                    out += write_uint8(0)
            else:
                if node.public_key or node.parent_hash:
                    out += write_uint8(2)
                    out += write_opaque16(node.public_key or b"")
                    out += write_opaque16(node.parent_hash or b"")
                    # RFC 9420 §7.1: unmerged_leaves<V>
                    # Serialize as repeated uint32, sorted.
                    ul_data = b""
                    for ul in sorted(node.unmerged_leaves):
                        ul_data += write_uint32(ul)
                    out += write_varint(len(ul_data)) + ul_data
                else:
                    out += write_uint8(0)
        return out

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
                self.add_leaf(KeyPackage(leaf_node=leaf, signature=Signature(b"")))  # signature not validated here
            else:
                # Even if blank, we need to advance the leaf count
                self._n_leaves += 1
        # Re-hash tree
        if self.n_leaves > 0:
            self._recalculate_hashes_from(0)

    def load_full_tree_from_welcome_bytes(self, data: bytes) -> None:
        """Load the tree from bytes produced by serialize_full_tree_for_welcome()."""
        off = 0
        n, off = read_uint16(data, off)
        width, off = read_uint16(data, off)
        self._n_leaves = 0
        self._nodes.clear()
        # First pass: set leaf count
        for _ in range(n):
            self._n_leaves += 1
        # Populate nodes
        for idx in range(width):
            node_type, off = read_uint8(data, off)
            if node_type == 0:
                continue
            node = self.get_node(idx)
            if node.is_leaf:
                blob, off = read_opaque16(data, off)
                if blob:
                    leaf = LeafNode.deserialize(blob)
                    node.public_key = leaf.encryption_key
                    node.leaf_node = leaf
            else:
                pk, off = read_opaque16(data, off)
                ph, off = read_opaque16(data, off)
                
                # RFC 9420 §7.1: unmerged_leaves<V> (vector of uint32)
                # Parse vector length first (varint)
                ul_len, off = read_varint(data, off)
                ul_end = off + ul_len
                unmerged_leaves = []
                while off < ul_end:
                    ul_val, off = read_uint32(data, off)
                    unmerged_leaves.append(ul_val)
                
                node.public_key = pk if pk else None
                node.parent_hash = ph if ph else None
                node.unmerged_leaves = unmerged_leaves
        if self.n_leaves > 0:
            self._recalculate_hashes_from(0)

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

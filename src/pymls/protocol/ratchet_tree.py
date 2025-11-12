from .key_packages import KeyPackage, LeafNode
from .data_structures import UpdatePath, Signature
from . import tree_math
from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import CommitValidationError
from ..codec.tls import write_uint16, write_opaque16, read_uint16, read_opaque16


class RatchetTreeNode:
    def __init__(self, is_leaf: bool):
        self.is_leaf = is_leaf
        self.public_key: bytes | None = None
        self.private_key: bytes | None = None
        self.parent_hash: bytes | None = None
        self.leaf_node: LeafNode | None = None
        self.hash: bytes | None = None


class RatchetTree:
    def __init__(self, crypto_provider: CryptoProvider):
        self._n_leaves = 0
        self._nodes: dict[int, RatchetTreeNode] = {}
        self._crypto_provider = crypto_provider

    @property
    def n_leaves(self):
        return self._n_leaves

    def get_node(self, index: int) -> RatchetTreeNode:
        if index not in self._nodes:
            # Create blank nodes on demand. A node is a leaf if its index is even.
            self._nodes[index] = RatchetTreeNode(index % 2 == 0)
        return self._nodes[index]

    def add_leaf(self, key_package: KeyPackage) -> int:
        leaf_index = self._n_leaves
        self._n_leaves += 1

        node_index = leaf_index * 2
        node = self.get_node(node_index)
        node.public_key = key_package.leaf_node.encryption_key
        node.leaf_node = key_package.leaf_node
        self._recalculate_hashes_from(node_index)
        return leaf_index

    def remove_leaf(self, index: int) -> None:
        node_index = index * 2
        node = self.get_node(node_index)
        node.public_key = None
        node.private_key = None
        node.leaf_node = None

        # Blank the direct path
        for p_idx in tree_math.direct_path(node_index, self.n_leaves):
            p_node = self.get_node(p_idx)
            p_node.public_key = None
            p_node.private_key = None

        self._recalculate_hashes_from(node_index)

    def update_leaf(self, index: int, leaf_node: LeafNode) -> None:
        node_index = index * 2
        node = self.get_node(node_index)
        node.public_key = leaf_node.encryption_key
        node.leaf_node = leaf_node
        self._recalculate_hashes_from(node_index)

    def _compute_parent_hash_for_leaf(self, leaf_index: int) -> bytes:
        """
        RFC-inspired parent hash binding (MVP):
        Derive a digest over the sequence of (parent_index || parent_hash) along the
        direct path from the leaf to the root. This binds the leaf to the current
        parent public keys/hashes and detects path tampering.
        """
        if self.n_leaves == 0:
            return b""
        leaf_node_index = leaf_index * 2
        # Ensure hashes are current
        self._recalculate_hashes_from(leaf_node_index)
        acc = b"parent-hash|"
        for p_idx in tree_math.direct_path(leaf_node_index, self.n_leaves):
            p = self.get_node(p_idx)
            ph = p.hash or b""
            acc += p_idx.to_bytes(4, "big") + ph
        # Finalize with a KDF extract for fixed-length output tied to KDF hash len
        return self._crypto_provider.kdf_extract(b"parent-hash", acc)

    def _recalculate_hashes_from(self, start_node_index: int):
        # Recalculate hash for the node itself
        self._hash_node(start_node_index)

        # Recalculate hashes up the direct path to the root
        path = tree_math.direct_path(start_node_index, self.n_leaves)
        for node_index in path:
            self._hash_node(node_index)

    def _hash_node(self, node_index: int):
        node = self.get_node(node_index)
        if node.is_leaf:
            if node.leaf_node:
                # RFC-style labeled hashing for leaf content
                node.hash = self._crypto_provider.expand_with_label(
                    self._crypto_provider.kdf_extract(b"", node.leaf_node.serialize()),
                    b"leaf hash",
                    b"",
                    self._crypto_provider.kdf_hash_len(),
                )
            else:
                node.hash = None
        else:
            left_child_hash = self.get_node(tree_math.left(node_index)).hash or b""
            right_child_hash = self.get_node(tree_math.right(node_index, self.n_leaves)).hash or b""
            node.hash = self._crypto_provider.kdf_extract(b"node_hash", left_child_hash + right_child_hash)

    def calculate_tree_hash(self) -> bytes:
        if self.n_leaves == 0:
            return b""
        root_index = tree_math.root(self.n_leaves)
        # Ensure hashes are up to date from root down
        self._hash_node(root_index)
        return self.get_node(root_index).hash or b""

    def create_update_path(self, committer_index: int, new_leaf_node: LeafNode) -> tuple[UpdatePath, bytes]:
        # Generate new keypairs for the direct path
        path_secrets = {}
        direct_path = tree_math.direct_path(committer_index * 2, self.n_leaves)
        for node_index in direct_path:
            priv_key, pub_key = self._crypto_provider.generate_key_pair()
            self._nodes[node_index].private_key = priv_key
            self._nodes[node_index].public_key = pub_key
            path_secrets[node_index] = self._crypto_provider.kdf_extract(b"", priv_key)

        # Encrypt path secrets for the copath
        encrypted_path_secrets: dict[int, list[bytes]] = {}
        copath = tree_math.copath(committer_index * 2, self.n_leaves)
        for node_index, secret in path_secrets.items():
            copath_node_index = tree_math.sibling(node_index, self.n_leaves)
            if copath_node_index in copath:
                # Collect recipient public keys under the copath subtree
                recipients = self._collect_subtree_recipients(copath_node_index)
                blobs: list[bytes] = []
                for pk in recipients:
                    enc, ct = self._crypto_provider.hpke_seal(pk, b"", b"", secret)
                    # Store as opaque16(enc) || opaque16(ct)
                    from .data_structures import serialize_bytes
                    blobs.append(serialize_bytes(enc) + serialize_bytes(ct))
                if blobs:
                    encrypted_path_secrets[copath_node_index] = blobs

        # Attach a simplified parent hash to the new leaf node
        parent_hash = self._compute_parent_hash_for_leaf(committer_index)
        leaf_for_path = LeafNode(
            encryption_key=new_leaf_node.encryption_key,
            signature_key=new_leaf_node.signature_key,
            credential=new_leaf_node.credential,
            capabilities=new_leaf_node.capabilities,
            parent_hash=parent_hash,
        )

        update_path = UpdatePath(leaf_for_path.serialize(), encrypted_path_secrets)
        commit_secret = self._crypto_provider.kdf_extract(b"", b"".join(path_secrets.values()))
        return update_path, commit_secret

    def merge_update_path(self, update_path: UpdatePath, committer_index: int) -> bytes:
        # Update leaf node
        provided_leaf = LeafNode.deserialize(update_path.leaf_node)
        # Verify simplified parent hash if present
        if provided_leaf.parent_hash:
            # Ensure current hashes are up to date before computing expected parent hash
            self._recalculate_hashes_from(committer_index * 2)
            expected = self._compute_parent_hash_for_leaf(committer_index)
            if expected != provided_leaf.parent_hash:
                raise CommitValidationError("parent_hash mismatch for provided leaf node")
        self.update_leaf(committer_index, provided_leaf)

        # Decrypt path secrets
        path_secrets = {}
        direct_path = tree_math.direct_path(committer_index * 2, self.n_leaves)
        for node_index in direct_path:
            # We can only decrypt secrets for nodes on our direct path's copath.
            # The update_path.nodes are indexed by the copath node index.
            sibling_index = tree_math.sibling(node_index, self.n_leaves)
            if sibling_index in update_path.nodes:
                node = self.get_node(node_index)
                if node.private_key:
                    # Try each recipient blob until decryption succeeds
                    from .data_structures import deserialize_bytes
                    for blob in update_path.nodes[sibling_index]:
                        try:
                            enc, rest = deserialize_bytes(blob)
                            ct, _ = deserialize_bytes(rest)
                            secret = self._crypto_provider.hpke_open(node.private_key, enc, b"", b"", ct)
                            path_secrets[node_index] = secret
                            break
                        except Exception:
                            continue

        # Update nodes with new public keys from path secrets
        for node_index, secret in path_secrets.items():
            priv_key, pub_key = self._crypto_provider.derive_key_pair(secret)
            self.get_node(node_index).private_key = priv_key
            self.get_node(node_index).public_key = pub_key

        self._recalculate_hashes_from(committer_index * 2)

        commit_secret = self._crypto_provider.kdf_extract(b"", b"".join(path_secrets.values()))
        return commit_secret

    def _collect_subtree_recipients(self, node_index: int) -> list[bytes]:
        """
        Gather recipient public keys under a subtree rooted at node_index.
        Only includes leaves with non-empty public keys.
        """
        recipients: list[bytes] = []
        max_index = tree_math.node_width(self.n_leaves) - 1

        def visit(idx: int):
            if idx < 0 or idx > max_index:
                return
            node = self.get_node(idx)
            if node.is_leaf:
                if node.public_key:
                    recipients.append(node.public_key)
                return
            # internal node
            try:
                visit(tree_math.left(idx))
                visit(tree_math.right(idx, self.n_leaves))
            except Exception:
                return

        visit(node_index)
        return recipients

    # --- Welcome ratchet_tree extension helpers (MVP: leaves only) ---
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
                self.add_leaf(KeyPackage(leaf, signature=Signature(b"")))  # signature not validated here
            else:
                # Even if blank, we need to advance the leaf count
                self._n_leaves += 1
        # Re-hash tree
        if self.n_leaves > 0:
            self._recalculate_hashes_from(0)

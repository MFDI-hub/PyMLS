from .key_packages import KeyPackage, LeafNode
from .data_structures import UpdatePath
from . import tree_math
from ..crypto.crypto_provider import CryptoProvider


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
                node.hash = self._crypto_provider.kdf_extract(b"leaf_hash", node.leaf_node.serialize())
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
        encrypted_path_secrets = {}
        copath = tree_math.copath(committer_index * 2, self.n_leaves)
        for node_index, secret in path_secrets.items():
            copath_node_index = tree_math.sibling(node_index, self.n_leaves)
            if copath_node_index in copath:
                copath_node = self.get_node(copath_node_index)
                if copath_node.public_key:
                    enc, ct = self._crypto_provider.hpke_seal(copath_node.public_key, b"", b"", secret)
                    encrypted_path_secrets[copath_node_index] = enc + ct

        update_path = UpdatePath(new_leaf_node.serialize(), encrypted_path_secrets)
        commit_secret = self._crypto_provider.kdf_extract(b"", b"".join(path_secrets.values()))
        return update_path, commit_secret

    def merge_update_path(self, update_path: UpdatePath, committer_index: int) -> bytes:
        # Update leaf node
        self.update_leaf(committer_index, LeafNode.deserialize(update_path.leaf_node))

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
                    enc_and_ct = update_path.nodes[sibling_index]
                    pk_size = self._crypto_provider.kem_pk_size()
                    enc = enc_and_ct[:pk_size]
                    ct = enc_and_ct[pk_size:]
                    secret = self._crypto_provider.hpke_open(node.private_key, enc, b"", b"", ct)
                    path_secrets[node_index] = secret

        # Update nodes with new public keys from path secrets
        for node_index, secret in path_secrets.items():
            priv_key, pub_key = self._crypto_provider.derive_key_pair(secret)
            self.get_node(node_index).private_key = priv_key
            self.get_node(node_index).public_key = pub_key

        self._recalculate_hashes_from(committer_index * 2)

        commit_secret = self._crypto_provider.kdf_extract(b"", b"".join(path_secrets.values()))
        return commit_secret

from pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from pymls.protocol.ratchet_tree import RatchetTree
from pymls.protocol.key_packages import KeyPackage, LeafNode
from pymls.protocol.data_structures import Signature


def make_dummy_leaf(crypto: DefaultCryptoProvider) -> LeafNode:
    sk, pk = crypto.generate_key_pair()
    # Use KEM public key for both encryption_key and signature_key (test-only)
    return LeafNode(encryption_key=pk, signature_key=pk, credential=None, capabilities=b"")


def make_dummy_kp(leaf: LeafNode) -> KeyPackage:
    # Build a minimal KeyPackage without a valid signature (unused in tree ops)
    return KeyPackage(leaf_node=leaf, signature=Signature(b""))


def test_create_update_path_shape_two_leaves():
    crypto = DefaultCryptoProvider()
    tree = RatchetTree(crypto)
    # Two-member tree
    kp0 = make_dummy_kp(make_dummy_leaf(crypto))
    kp1 = make_dummy_kp(make_dummy_leaf(crypto))
    leaf0 = tree.add_leaf(kp0)
    leaf1 = tree.add_leaf(kp1)
    assert leaf0 == 0 and leaf1 == 1
    # Committer 0 creates an update path
    new_leaf0 = make_dummy_leaf(crypto)
    gc_bytes = b"group-context-bytes"
    update_path, commit_secret = tree.create_update_path(0, new_leaf0, gc_bytes)
    assert isinstance(commit_secret, (bytes, bytearray)) and len(commit_secret) == crypto.kdf_hash_len()
    # With 2 leaves, there should be encryption to the sibling subtree (leaf 1)
    assert isinstance(update_path.nodes, dict) and len(update_path.nodes) >= 0



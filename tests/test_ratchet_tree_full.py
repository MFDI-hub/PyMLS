import os

from src.pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from src.pymls.protocol.ratchet_tree import RatchetTree
from src.pymls.protocol.key_packages import KeyPackage, LeafNode
from src.pymls.protocol.data_structures import Credential, Signature


def _dummy_leaf(enc_pk: bytes, sig_pk: bytes) -> LeafNode:
    cred = Credential(identity=b"user", public_key=sig_pk)
    return LeafNode(
        encryption_key=enc_pk,
        signature_key=sig_pk,
        credential=cred,
        capabilities=b"",
        parent_hash=b"",
    )


def test_full_tree_welcome_roundtrip():
    crypto = DefaultCryptoProvider()
    rt = RatchetTree(crypto)
    # Two dummy leaves
    sk1, pk1 = crypto.generate_key_pair()
    sk2, pk2 = crypto.generate_key_pair()
    leaf1 = _dummy_leaf(pk1, os.urandom(32))
    leaf2 = _dummy_leaf(pk2, os.urandom(32))
    rt.add_leaf(KeyPackage(leaf1, Signature(b"")))
    rt.add_leaf(KeyPackage(leaf2, Signature(b"")))

    data = rt.serialize_full_tree_for_welcome()

    rt2 = RatchetTree(crypto)
    rt2.load_full_tree_from_welcome_bytes(data)
    assert rt2.n_leaves == rt.n_leaves
    assert rt2.get_node(0).leaf_node is not None
    assert rt2.get_node(2).leaf_node is not None


def test_parent_hash_changes_on_path_update():
    crypto = DefaultCryptoProvider()
    rt = RatchetTree(crypto)
    sk1, pk1 = crypto.generate_key_pair()
    leaf1 = _dummy_leaf(pk1, os.urandom(32))
    rt.add_leaf(KeyPackage(leaf1, Signature(b"")))
    ph_before = rt._compute_parent_hash_for_leaf(0)
    # Force an update path to change direct path nodes
    _update_path, _commit_secret = rt.create_update_path(0, leaf1)
    ph_after = rt._compute_parent_hash_for_leaf(0)
    assert ph_before != ph_after


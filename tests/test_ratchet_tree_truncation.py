from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
from rfc9420.protocol.ratchet_tree import RatchetTree
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature


def _make_dummy_leaf(enc_key: bytes, sig_key: bytes) -> LeafNode:
    # Minimal credential matching signature key
    cred = Credential(identity=b"user", public_key=sig_key)
    return LeafNode(
        encryption_key=enc_key, signature_key=sig_key, credential=cred, capabilities=b""
    )


def test_truncate_immediately_on_remove():
    crypto = DefaultCryptoProvider()
    tree = RatchetTree(crypto)

    # Two leaves
    ln1 = _make_dummy_leaf(b"\x01\x01", b"\xaa\xaa")
    ln2 = _make_dummy_leaf(b"\x02\x02", b"\xbb\xbb")
    kp1 = KeyPackage(leaf_node=ln1, signature=Signature(b""))
    kp2 = KeyPackage(leaf_node=ln2, signature=Signature(b""))

    tree.add_leaf(kp1)
    tree.add_leaf(kp2)
    assert tree.n_leaves == 2

    # Compute reference hash for single-leaf tree
    tree_ref = RatchetTree(crypto)
    tree_ref.add_leaf(kp1)
    h_ref = tree_ref.calculate_tree_hash()

    # Remove rightmost leaf; n_leaves should truncate to 1 and hash should match single-leaf ref
    tree.remove_leaf(1)
    assert tree.n_leaves == 1
    assert tree.calculate_tree_hash() == h_ref

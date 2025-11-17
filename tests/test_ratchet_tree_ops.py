import unittest
from pymls.protocol.ratchet_tree import RatchetTree
from pymls import DefaultCryptoProvider
from pymls.protocol.key_packages import KeyPackage, LeafNode
from pymls.protocol.data_structures import Credential, Signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def make_kp(identity: bytes):
    sk_sig = Ed25519PrivateKey.generate()
    pk_sig = sk_sig.public_key()
    sk_kem = X25519PrivateKey.generate()
    pk_kem = sk_kem.public_key()
    cred = Credential(identity=identity, public_key=pk_sig.public_bytes_raw())
    leaf = LeafNode(
        encryption_key=pk_kem.public_bytes_raw(),
        signature_key=pk_sig.public_bytes_raw(),
        credential=cred,
        capabilities=b"",
        parent_hash=b"",
    )
    crypto = DefaultCryptoProvider()
    sig = crypto.sign_with_label(sk_sig.private_bytes_raw(), b"KeyPackageTBS", leaf.serialize())
    kp = KeyPackage(leaf_node=leaf, signature=Signature(sig))
    return kp


class TestRatchetTreeOps(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        self.tree = RatchetTree(self.crypto)

    def test_add_and_tree_hash(self):
        kp1 = make_kp(b"A")
        idx = self.tree.add_leaf(kp1)
        self.assertEqual(idx, 0)
        th = self.tree.calculate_tree_hash()
        self.assertTrue(th)

    def test_update_path_and_merge(self):
        kp1 = make_kp(b"A")
        kp2 = make_kp(b"B")
        self.tree.add_leaf(kp1)
        self.tree.add_leaf(kp2)
        ln = self.tree.get_node(0).leaf_node
        path, secret = self.tree.create_update_path(0, ln, b"")
        self.assertTrue(secret)
        commit_secret = self.tree.merge_update_path(path, 0, b"")
        self.assertTrue(commit_secret)

    def test_welcome_tree_extension_roundtrip(self):
        kp1 = make_kp(b"A")
        kp2 = make_kp(b"B")
        self.tree.add_leaf(kp1)
        self.tree.add_leaf(kp2)
        blob = self.tree.serialize_tree_for_welcome()
        t2 = RatchetTree(self.crypto)
        t2.load_tree_from_welcome_bytes(blob)
        self.assertEqual(t2.n_leaves, self.tree.n_leaves)


if __name__ == "__main__":
    unittest.main()



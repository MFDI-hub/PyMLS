import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519

from src.pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from src.pymls.protocol.key_packages import KeyPackage, LeafNode
from src.pymls.protocol.data_structures import GroupContext, GroupInfo, Signature
from src.pymls.protocol.ratchet_tree import RatchetTree
from src.pymls.extensions.extensions import Extension, ExtensionType, serialize_extensions


class TestGroupInfoVerification(unittest.TestCase):
    def test_groupinfo_signature_verification_with_tree_extension(self):
        crypto = DefaultCryptoProvider(0x0001)  # Ed25519 suite
        # Build a one-leaf tree with known signature key
        sk = ed25519.Ed25519PrivateKey.generate()
        pk = sk.public_key().public_bytes_raw()
        leaf = LeafNode(
            encryption_key=pk,  # reuse pk for simplicity in this test
            signature_key=pk,
            credential=None,
            capabilities=b"",
            parent_hash=b"",
        )
        kp = KeyPackage(leaf, signature=Signature(b""))
        tree = RatchetTree(crypto)
        tree.add_leaf(kp)
        rt_bytes = tree.serialize_tree_for_welcome()
        exts = [Extension(ExtensionType.RATCHET_TREE, rt_bytes)]
        ext_bytes = serialize_extensions(exts)

        gc = GroupContext(group_id=b"g", epoch=1, tree_hash=tree.calculate_tree_hash(), confirmed_transcript_hash=b"x")
        gi_unsigned = GroupInfo(gc, Signature(b""), ext_bytes)
        sig = sk.sign(gi_unsigned.tbs_serialize())
        gi = GroupInfo(gc, Signature(sig), ext_bytes)
        # Re-parse and collect candidate keys from extension, verify signature
        tbs = gi.tbs_serialize()
        verified = False
        tmp = RatchetTree(crypto)
        tmp.load_tree_from_welcome_bytes(rt_bytes)
        for i in range(tmp.n_leaves):
            node = tmp.get_node(i * 2)
            if node.leaf_node and node.leaf_node.signature_key:
                try:
                    crypto.verify(node.leaf_node.signature_key, tbs, gi.signature.value)
                    verified = True
                    break
                except Exception:
                    continue
        self.assertTrue(verified, "GroupInfo signature should verify with a leaf signer from the tree")



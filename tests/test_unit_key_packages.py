import unittest

from rfc9420 import DefaultCryptoProvider
from rfc9420.extensions.extensions import Extension, ExtensionType, build_capabilities_data
from rfc9420.mls.exceptions import InvalidSignatureError
from rfc9420.protocol.key_packages import KeyPackage, LeafNode, LeafNodeSource
from tests.helpers import make_member


class TestUnitKeyPackages(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_key_package_verify_happy_path(self):
        kp = make_member(b"user-a", self.crypto).key_package
        kp.verify(self.crypto)

    def test_leaf_source_enforced(self):
        member = make_member(b"user-b", self.crypto)
        leaf = member.key_package.leaf_node
        assert leaf is not None
        bad_leaf = LeafNode(
            encryption_key=leaf.encryption_key,
            signature_key=leaf.signature_key,
            credential=leaf.credential,
            capabilities=leaf.capabilities,
            leaf_node_source=LeafNodeSource.UPDATE,
            parent_hash=b"\x01",
            extensions=leaf.extensions,
            signature=leaf.signature,
        )
        bad_kp = KeyPackage(
            version=member.key_package.version,
            cipher_suite=member.key_package.cipher_suite,
            init_key=member.key_package.init_key,
            leaf_node=bad_leaf,
            extensions=member.key_package.extensions,
            signature=member.key_package.signature,
        )
        with self.assertRaises(InvalidSignatureError):
            bad_kp.verify(self.crypto)

    def test_extension_must_be_in_capabilities(self):
        member = make_member(b"user-c", self.crypto)
        ext = Extension(ext_type=ExtensionType.APPLICATION_ID, data=b"x")
        leaf = member.key_package.leaf_node
        assert leaf is not None
        bad_leaf = LeafNode(
            encryption_key=leaf.encryption_key,
            signature_key=leaf.signature_key,
            credential=leaf.credential,
            capabilities=build_capabilities_data([1], []),
            leaf_node_source=leaf.leaf_node_source,
            lifetime_not_before=leaf.lifetime_not_before,
            lifetime_not_after=leaf.lifetime_not_after,
            extensions=leaf.extensions,
            signature=leaf.signature,
            parent_hash=leaf.parent_hash,
        )
        bad_kp = KeyPackage(
            version=member.key_package.version,
            cipher_suite=member.key_package.cipher_suite,
            init_key=member.key_package.init_key,
            leaf_node=bad_leaf,
            extensions=[ext],
            signature=member.key_package.signature,
        )
        with self.assertRaises(Exception):
            bad_kp.verify(self.crypto)


if __name__ == "__main__":
    unittest.main()

import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rfc9420 import Group, DefaultCryptoProvider
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature


def _ed25519_keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    skb = sk.private_bytes_raw()
    pkb = pk.public_bytes_raw()
    return skb, pkb


def _x25519_keypair():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    skb = sk.private_bytes_raw()
    pkb = pk.public_bytes_raw()
    return skb, pkb



def _make_key_package(identity: bytes) -> tuple[KeyPackage, bytes, bytes]:
    """
    Return (KeyPackage, kem_sk, sig_sk) for a member.
    """
    kem_sk, kem_pk = _x25519_keypair()
    sig_sk, sig_pk = _ed25519_keypair()
    cred = Credential(identity=identity, public_key=sig_pk)
    # 1. Create LeafNode (unsigned initially)
    leaf = LeafNode(
        encryption_key=kem_pk,
        signature_key=sig_pk,
        credential=cred,
        capabilities=b"",
        signature=b""
    )
    crypto = DefaultCryptoProvider()
    # 2. Sign LeafNodeTBS
    leaf_tbs = leaf.tbs_serialize()
    leaf_sig = crypto.sign_with_label(sig_sk, b"LeafNodeTBS", leaf_tbs)
    # 3. Create signed LeafNode
    # Since it's frozen, create new instance
    signed_leaf = LeafNode(
        encryption_key=leaf.encryption_key,
        signature_key=leaf.signature_key,
        credential=leaf.credential,
        capabilities=leaf.capabilities,
        leaf_node_source=leaf.leaf_node_source,
        extensions=leaf.extensions,
        signature=Signature(leaf_sig).value,
        parent_hash=leaf.parent_hash
    )
    
    # 4. Create KeyPackage (unsigned initially)
    kp = KeyPackage(leaf_node=signed_leaf, init_key=kem_pk, signature=Signature(b""))
    
    # 5. Sign KeyPackageTBS
    kp_tbs = kp.tbs_serialize()
    kp_sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", kp_tbs)
    
    # 6. Final signed KeyPackage
    final_kp = KeyPackage(
         version=kp.version,
         cipher_suite=kp.cipher_suite,
         init_key=kp.init_key,
         leaf_node=signed_leaf,
         signature=Signature(kp_sig)
    )
    return final_kp, kem_sk, sig_sk


class TestGroupFlow(unittest.TestCase):
    def test_add_join_and_message(self):
        try:
            import cryptography.hazmat.primitives.hpke  # noqa: F401
        except Exception:
            self.skipTest("HPKE support not available in this cryptography build")
        crypto = DefaultCryptoProvider()
        # Creator A
        kp_a, kem_sk_a, sig_sk_a = _make_key_package(b"userA")
        group = Group.create(b"group1", kp_a, crypto)
        self.assertEqual(group.epoch, 0)

        # Joiner B
        kp_b, kem_sk_b, sig_sk_b = _make_key_package(b"userB")

        # A proposes to add B and commits
        prop = group.add(kp_b, sig_sk_a)
        group.process_proposal(prop, 0)
        commit_pt, welcomes = group.commit(sig_sk_a)
        self.assertTrue(len(welcomes) >= 1)
        self.assertEqual(group.epoch, 1)

        # B joins from welcome
        group_b = Group.join_from_welcome(welcomes[0], kem_sk_b, crypto)
        self.assertEqual(group_b.group_id, group.group_id)
        self.assertEqual(group_b.epoch, group.epoch)

        # Send application data from A to B
        ciphertext = group.protect(b"hello")
        sender_idx, plaintext = group_b.unprotect(ciphertext)
        self.assertEqual(sender_idx, 0)
        self.assertEqual(plaintext, b"hello")


if __name__ == "__main__":
    unittest.main()

import unittest
from src.pymls import DefaultCryptoProvider
from src.pymls.mls.group import Group
from src.pymls.protocol.key_packages import KeyPackage, LeafNode
from src.pymls.protocol.data_structures import Credential, Signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def member(identity: bytes):
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
    sig = sk_sig.sign(leaf.serialize())
    kp = KeyPackage(leaf, Signature(sig))
    return kp, sk_kem.private_bytes_raw(), sk_sig.private_bytes_raw()


class TestMLSGroupExternalAndPersist(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_persistence(self):
        kp, kem_sk, sig_sk = member(b"A")
        g = Group.create(b"gid", kp, self.crypto)
        bts = g._inner.to_bytes()
        g2 = Group(g.group_id, g._inner) if False else None  # placeholder
        from src.pymls.protocol.mls_group import MLSGroup
        g3 = MLSGroup.from_bytes(bts, self.crypto)
        self.assertEqual(g3.get_group_id(), g.group_id)

    def test_external_commit_processing(self):
        # Build group A and clone into B
        kp, kem_sk, sig_sk = member(b"A")
        from src.pymls.protocol.mls_group import MLSGroup
        gA = MLSGroup.create(b"gid2", kp, self.crypto)
        pt, _ = gA.create_commit(sig_sk)
        # Resign the plaintext with external private key and attach membership tag
        from src.pymls.protocol.messages import sign_authenticated_content, attach_membership_tag, ContentType
        tbs = pt.auth_content.tbs
        # Access external private key from gA (MVP internals)
        ext_sk = gA._external_private_key
        pt_ext = sign_authenticated_content(
            group_id=tbs.group_id,
            epoch=tbs.epoch,
            sender_leaf_index=tbs.sender_leaf_index,
            authenticated_data=tbs.authenticated_data,
            content_type=ContentType.COMMIT,
            content=tbs.framed_content.content,
            signing_private_key=ext_sk,
            crypto=self.crypto,
        )
        pt_ext = attach_membership_tag(pt_ext, gA._key_schedule.membership_key, self.crypto)
        # Clone state into B then process external commit
        bts = gA.to_bytes()
        gB = MLSGroup.from_bytes(bts, self.crypto)
        old_epoch = gB.get_epoch()
        gB.process_external_commit(pt_ext)
        self.assertEqual(gB.get_epoch(), old_epoch + 1)


if __name__ == "__main__":
    unittest.main()



import unittest
from rfc9420 import DefaultCryptoProvider
from rfc9420.mls.group import Group
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature
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
    crypto = DefaultCryptoProvider()
    sig = crypto.sign_with_label(sk_sig.private_bytes_raw(), b"KeyPackageTBS", leaf.serialize())
    kp = KeyPackage(leaf_node=leaf, signature=Signature(sig))
    return kp, sk_kem.private_bytes_raw(), sk_sig.private_bytes_raw()


class TestMLSGroupExternalAndPersist(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_persistence(self):
        kp, kem_sk, sig_sk = member(b"A")
        g = Group.create(b"gid", kp, self.crypto)
        bts = g._inner.to_bytes()
        from rfc9420.protocol.mls_group import MLSGroup

        g3 = MLSGroup.from_bytes(bts, self.crypto)
        self.assertEqual(g3.get_group_id(), g.group_id)

    def test_external_commit_processing(self):
        # Build group A and clone into B
        kp, kem_sk, sig_sk = member(b"A")
        from rfc9420.protocol.mls_group import MLSGroup

        gA = MLSGroup.create(b"gid2", kp, self.crypto)
        pt, _ = gA.create_commit(sig_sk)
        # Resign the plaintext with external private key and attach membership tag
        from rfc9420.protocol.messages import (
            sign_authenticated_content,
            attach_membership_tag,
            ContentType,
        )

        tbs = pt.auth_content.tbs
        fc = tbs.framed_content
        # Access external private key from gA (MVP internals)
        ext_sk = gA._external_private_key
        pt_ext = sign_authenticated_content(
            group_id=fc.group_id,
            epoch=fc.epoch,
            sender_leaf_index=fc.sender.sender if hasattr(fc.sender, 'sender') else int(fc.sender),
            authenticated_data=fc.authenticated_data,
            content_type=ContentType.COMMIT,
            content=fc.content,
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

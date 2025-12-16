import unittest

from rfc9420 import DefaultCryptoProvider
from rfc9420.mls.group import Group
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _member(identity: bytes):
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
    kp = KeyPackage(leaf_node=leaf, signature=Signature(sig))
    return kp, sk_kem.private_bytes_raw(), sk_sig.private_bytes_raw()


class TestNegative(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_process_commit_missing_referenced_proposal_raises(self):
        # Setup group with one member
        kp_a, kem_sk_a, sig_sk_a = _member(b"A")
        group = Group.create(b"g", kp_a, self.crypto)
        # Create a normal commit (no proposals) to get a valid commit container
        pt, welcomes = group.commit(sig_sk_a)
        # Tamper plaintext framed content by appending a fake reference in the commit body
        from rfc9420.protocol.data_structures import Commit, ProposalOrRef, ProposalOrRefType

        commit = Commit.deserialize(pt.auth_content.tbs.framed_content.content)
        tampered = Commit(
            commit.path,
            commit.proposals + [ProposalOrRef(ProposalOrRefType.REFERENCE, reference=b"\x01")],
            commit.signature,
        )
        from rfc9420.protocol.messages import (
            sign_authenticated_content,
            attach_membership_tag,
            ContentType,
        )

        pt_tampered = sign_authenticated_content(
            group_id=group.group_id,
            epoch=group.epoch,
            sender_leaf_index=0,
            authenticated_data=b"",
            content_type=ContentType.COMMIT,
            content=tampered.serialize(),
            signing_private_key=sig_sk_a,
            crypto=self.crypto,
        )
        pt_tampered = attach_membership_tag(
            pt_tampered, group._inner._key_schedule.membership_key, self.crypto
        )
        with self.assertRaises(ValueError):
            group.apply_commit(pt_tampered, 0)

    def test_invalid_commit_signature_raises(self):
        kp_a, kem_sk_a, sig_sk_a = _member(b"A")
        group = Group.create(b"g2", kp_a, self.crypto)
        pt, _ = group.commit(sig_sk_a)
        # Zero out signature bytes
        auth = pt.auth_content
        bad = type(pt)(type(auth)(auth.tbs, b"\x00" * len(auth.signature), auth.membership_tag))
        with self.assertRaises(Exception):
            group.apply_commit(bad, 0)


if __name__ == "__main__":
    unittest.main()

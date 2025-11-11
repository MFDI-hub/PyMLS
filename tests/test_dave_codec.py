import unittest

from src.pymls.dave.codec import (
    pack_key_package,
    unpack_key_package,
    pack_proposals,
    unpack_proposals,
    pack_commit_or_welcome,
    unpack_commit_or_welcome,
    pack_announce_commit,
    unpack_announce_commit,
    pack_welcome,
    unpack_welcome,
)
from src.pymls.protocol.key_packages import KeyPackage, LeafNode
from src.pymls.protocol.data_structures import Credential, Signature, AddProposal, Commit, Welcome, MLSVersion, CipherSuite
from src.pymls.crypto.hpke import KEM, KDF, AEAD


class DummyCrypto:
    def sign(self, sk: bytes, data: bytes) -> bytes:
        return b"s"


class TestDaveCodec(unittest.TestCase):
    def test_key_package_roundtrip(self):
        kp = KeyPackage(
            leaf_node=LeafNode(
                encryption_key=b"e",
                signature_key=b"p",
                credential=Credential(b"id", b"pk"),
                capabilities=b"",
            ),
            signature=Signature(b"s"),
        )
        pkt = pack_key_package(1, kp)
        seq, kp2, _ = unpack_key_package(pkt, 0)
        self.assertEqual(seq, 1)
        self.assertEqual(kp2.leaf_node.credential.identity, b"id")

    def test_proposals_roundtrip(self):
        proposals = [AddProposal(b"kp")]
        sig = b"sig"
        pkt = pack_proposals(5, proposals, sig)
        seq, props2, s2, _ = unpack_proposals(pkt, 0)
        self.assertEqual(seq, 5)
        self.assertEqual(len(props2), 1)
        self.assertEqual(s2, sig)

    def test_commit_and_welcome_roundtrip(self):
        commit = Commit(path=None, removes=[], adds=[], signature=Signature(b""))
        pkt_c = pack_commit_or_welcome(2, 9, 0, (commit, b"sig"))
        seq, tid, kind, payload, _ = unpack_commit_or_welcome(pkt_c, 0)
        self.assertEqual((seq, tid, kind), (2, 9, 0))

        welcome = Welcome(MLSVersion.MLS10, CipherSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM), [], b"gi")
        pkt_w = pack_commit_or_welcome(3, 10, 1, welcome)
        seq2, tid2, kind2, payload2, _ = unpack_commit_or_welcome(pkt_w, 0)
        self.assertEqual((seq2, tid2, kind2), (3, 10, 1))

        pkt_ac = pack_announce_commit(4, 11, commit, b"sig")
        seq3, tid3, c3, s3, _ = unpack_announce_commit(pkt_ac, 0)
        self.assertEqual((seq3, tid3), (4, 11))

        pkt_w2 = pack_welcome(6, 12, welcome)
        seq4, tid4, w4, _ = unpack_welcome(pkt_w2, 0)
        self.assertEqual((seq4, tid4), (6, 12))


if __name__ == "__main__":
    unittest.main()


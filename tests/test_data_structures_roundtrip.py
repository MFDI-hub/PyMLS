import unittest
from pymls.protocol.data_structures import (
    AddProposal, UpdateProposal, RemoveProposal, PreSharedKeyProposal, ReInitProposal, ExternalInitProposal,
    Signature, UpdatePath, Commit, Welcome, MLSVersion, CipherSuite, EncryptedGroupSecrets, ProposalOrRef, ProposalOrRefType
)
from pymls.protocol.data_structures import serialize_bytes
from pymls.crypto.ciphersuites import KEM, KDF, AEAD


class TestDataStructuresRoundtrip(unittest.TestCase):
    def test_proposals_roundtrip(self):
        items = [
            AddProposal(b"kp"),
            UpdateProposal(b"ln"),
            RemoveProposal(1),
            PreSharedKeyProposal(b"id"),
            ReInitProposal(b"new"),
            ExternalInitProposal(b"pk"),
        ]
        for x in items:
            y = type(x).deserialize(x.serialize())
            self.assertEqual(type(x), type(y))

    def test_commit_roundtrip(self):
        up = UpdatePath(serialize_bytes(b"ln"), {1: [serialize_bytes(b"a") + serialize_bytes(b"b")]})
        proposals = [
            ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=RemoveProposal(1)),
            ProposalOrRef(ProposalOrRefType.PROPOSAL, proposal=AddProposal(b"kp")),
            ProposalOrRef(ProposalOrRefType.REFERENCE, reference=b"ref"),
        ]
        c = Commit(path=up, proposals=proposals, signature=Signature(b"sig"))
        d = Commit.deserialize(c.serialize())
        # Check that proposals vector round-trips with expected types and payloads
        assert len(d.proposals) == 3
        assert d.proposals[0].typ == ProposalOrRefType.PROPOSAL and isinstance(d.proposals[0].proposal, RemoveProposal) and d.proposals[0].proposal.removed == 1
        assert d.proposals[1].typ == ProposalOrRefType.PROPOSAL and isinstance(d.proposals[1].proposal, AddProposal) and d.proposals[1].proposal.key_package == b"kp"
        assert d.proposals[2].typ == ProposalOrRefType.REFERENCE and d.proposals[2].reference == b"ref"

    def test_welcome_roundtrip(self):
        cs = CipherSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        w = Welcome(MLSVersion.MLS10, cs, [EncryptedGroupSecrets(b"e", b"c")], b"egi")
        x = Welcome.deserialize(w.serialize())
        self.assertEqual(x.version, w.version)
        self.assertEqual(x.cipher_suite.kem, w.cipher_suite.kem)
        self.assertEqual(len(x.secrets), 1)


if __name__ == "__main__":
    unittest.main()



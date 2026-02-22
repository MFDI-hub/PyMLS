import unittest

from rfc9420.codec.mls import (
    decode_commit_message,
    decode_proposals_message,
    decode_welcome,
    encode_commit_message,
    encode_proposals_message,
    encode_welcome,
)
from rfc9420.crypto.ciphersuites import AEAD, KDF, KEM
from rfc9420.protocol.data_structures import (
    AddProposal,
    CipherSuite,
    EncryptedGroupSecrets,
    GroupContext,
    GroupInfo,
    MLSVersion,
    Signature,
    Welcome,
)
from rfc9420.protocol.data_structures import Commit
from tests.helpers import make_member


class TestUnitCodecMLS(unittest.TestCase):
    def test_welcome_roundtrip(self):
        cs = CipherSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        group_info = GroupInfo(
            group_context=GroupContext(
                group_id=b"gid",
                epoch=0,
                tree_hash=b"\x00" * 32,
                confirmed_transcript_hash=b"\x11" * 32,
            ),
            signer_leaf_index=0,
            signature=Signature(b"sig"),
            confirmation_tag=b"\x22" * 32,
            extensions=b"",
        )
        welcome = Welcome(
            version=MLSVersion.MLS10,
            cipher_suite=cs,
            secrets=[EncryptedGroupSecrets(kem_output=b"k", ciphertext=b"c")],
            encrypted_group_info=group_info.serialize(),
        )
        dec = decode_welcome(encode_welcome(welcome))
        self.assertEqual(dec.version, welcome.version)
        self.assertEqual(len(dec.secrets), 1)

    def test_commit_encode_decode(self):
        commit = Commit(path=None, proposals=[])
        sig = b"signature"
        decoded_commit, decoded_sig = decode_commit_message(encode_commit_message(commit, sig))
        self.assertEqual(len(decoded_commit.proposals), 0)
        self.assertEqual(decoded_sig, sig)

    def test_proposals_encode_decode(self):
        kp = make_member(b"user-a").key_package
        proposals = [AddProposal(key_package=kp.serialize())]
        decoded, sig = decode_proposals_message(encode_proposals_message(proposals, b"ignored"))
        self.assertEqual(len(decoded), 1)
        self.assertEqual(sig, b"")


if __name__ == "__main__":
    unittest.main()

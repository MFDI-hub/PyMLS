"""Comprehensive tests for rfc9420.codec.mls module."""

import unittest

from rfc9420.codec.mls import (
    encode_welcome,
    decode_welcome,
    encode_commit_message,
    decode_commit_message,
    encode_proposals_message,
    decode_proposals_message,
)
from rfc9420.protocol.data_structures import (
    Welcome,
    Commit,
    AddProposal,
    Signature,
    EncryptedGroupSecrets,
    GroupInfo,
    GroupContext,
    CipherSuite,
    MLSVersion,
    UpdatePath,
)
from rfc9420.protocol.key_packages import LeafNode
from rfc9420.protocol.data_structures import Credential
from rfc9420 import DefaultCryptoProvider
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class TestCodecMLS(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def _make_leaf_node(self, identity: bytes):
        """Helper to create a LeafNode."""
        sig_sk = Ed25519PrivateKey.generate()
        sig_pk = sig_sk.public_key()
        kem_sk = X25519PrivateKey.generate()
        kem_pk = kem_sk.public_key()
        cred = Credential(identity=identity, public_key=sig_pk.public_bytes_raw())
        return LeafNode(
            encryption_key=kem_pk.public_bytes_raw(),
            signature_key=sig_pk.public_bytes_raw(),
            credential=cred,
            capabilities=b"",
            parent_hash=b"",
        )

    def test_encode_decode_welcome_roundtrip(self):
        """Test Welcome encoding and decoding roundtrip."""
        # Create a minimal Welcome message
        sig_sk = Ed25519PrivateKey.generate()
        sig_pk = sig_sk.public_key()

        # Create encrypted group secrets
        enc_secrets = EncryptedGroupSecrets(kem_output=b"\x00" * 16, ciphertext=b"encrypted_data")

        # Create group info
        group_context = GroupContext(
            group_id=b"test_group",
            epoch=0,
            tree_hash=b"\x00" * 32,
            confirmed_transcript_hash=b"\x00" * 32,
        )
        group_info = GroupInfo(
            group_context=group_context,
            signature=Signature(sig_pk.public_bytes_raw()),
            extensions=b"",
            confirmation_tag=b"\x00" * 32,
            signer_leaf_index=0,
        )

        cs = CipherSuite(
            self.crypto.active_ciphersuite.kem,
            self.crypto.active_ciphersuite.kdf,
            self.crypto.active_ciphersuite.aead,
        )
        # In this codec, Welcome carries encrypted_group_info bytes; keep it simple
        welcome = Welcome(
            version=MLSVersion.MLS10,
            cipher_suite=cs,
            secrets=[enc_secrets],
            encrypted_group_info=group_info.serialize(),
        )

        # Encode and decode
        encoded = encode_welcome(welcome)
        decoded = decode_welcome(encoded)

        self.assertEqual(decoded.version, welcome.version)
        self.assertEqual(decoded.cipher_suite.kem, welcome.cipher_suite.kem)
        self.assertEqual(len(decoded.secrets), len(welcome.secrets))
        self.assertEqual(decoded.secrets[0].kem_output, welcome.secrets[0].kem_output)
        self.assertEqual(decoded.secrets[0].ciphertext, welcome.secrets[0].ciphertext)

    def test_encode_decode_commit_roundtrip(self):
        """Test Commit encoding and decoding roundtrip."""
        # Create a minimal Commit
        leaf = self._make_leaf_node(b"test")
        sig_sk = Ed25519PrivateKey.generate()
        sig_bytes = sig_sk.sign(b"test_data")

        update_path = UpdatePath(leaf_node=leaf.serialize(), nodes={})

        commit = Commit(
            path=update_path,
            proposals=[],
            signature=Signature(sig_bytes),
        )

        # Encode and decode
        encoded = encode_commit_message(commit, sig_bytes)
        decoded_commit, decoded_sig = decode_commit_message(encoded)

        self.assertEqual(len(decoded_commit.proposals), len(commit.proposals))
        self.assertEqual(decoded_sig, sig_bytes)

    def test_encode_decode_proposals_roundtrip(self):
        """Test Proposals encoding and decoding roundtrip."""
        # Create test proposals
        leaf1 = self._make_leaf_node(b"user1")
        leaf2 = self._make_leaf_node(b"user2")

        sig_sk1 = Ed25519PrivateKey.generate()
        sig1 = sig_sk1.sign(leaf1.serialize())

        sig_sk2 = Ed25519PrivateKey.generate()
        sig2 = sig_sk2.sign(leaf2.serialize())

        from rfc9420.protocol.key_packages import KeyPackage

        kp1 = KeyPackage(leaf_node=leaf1, signature=Signature(sig1))
        kp2 = KeyPackage(leaf_node=leaf2, signature=Signature(sig2))

        proposals = [
            AddProposal(key_package=kp1.serialize()),
            AddProposal(key_package=kp2.serialize()),
        ]

        # Encode and decode
        encoded = encode_proposals_message(proposals, b"ignored_signature")
        decoded_proposals, decoded_sig = decode_proposals_message(encoded)

        self.assertEqual(len(decoded_proposals), len(proposals))
        self.assertEqual(decoded_sig, b"")
        self.assertIsInstance(decoded_proposals[0], AddProposal)
        self.assertIsInstance(decoded_proposals[1], AddProposal)

    def test_encode_decode_empty_proposals(self):
        """Test encoding and decoding empty proposals list."""
        proposals = []
        encoded = encode_proposals_message(proposals, b"")
        decoded_proposals, decoded_sig = decode_proposals_message(encoded)

        self.assertEqual(len(decoded_proposals), 0)
        self.assertEqual(decoded_sig, b"")

    def test_encode_decode_single_proposal(self):
        """Test encoding and decoding a single proposal."""
        leaf = self._make_leaf_node(b"user")
        sig_sk = Ed25519PrivateKey.generate()
        sig = sig_sk.sign(leaf.serialize())

        from rfc9420.protocol.key_packages import KeyPackage

        kp = KeyPackage(leaf_node=leaf, signature=Signature(sig))

        proposals = [AddProposal(key_package=kp.serialize())]
        encoded = encode_proposals_message(proposals, b"")
        decoded_proposals, _ = decode_proposals_message(encoded)

        self.assertEqual(len(decoded_proposals), 1)
        self.assertIsInstance(decoded_proposals[0], AddProposal)

    def test_decode_proposals_insufficient_data(self):
        """Test decoding proposals with insufficient data."""
        # Empty buffer should return empty list
        decoded_proposals, decoded_sig = decode_proposals_message(b"")
        self.assertEqual(len(decoded_proposals), 0)
        self.assertEqual(decoded_sig, b"")


if __name__ == "__main__":
    unittest.main()

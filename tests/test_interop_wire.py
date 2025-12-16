"""Comprehensive tests for pymls.interop.wire module."""

import unittest

from rfc9420.interop.wire import (
    encode_handshake,
    decode_handshake,
    encode_application,
    decode_application,
)
from rfc9420.protocol.messages import (
    MLSPlaintext,
    MLSCiphertext,
    ContentType,
    FramedContent,
    AuthenticatedContentTBS,
    AuthenticatedContent,
)
from rfc9420 import DefaultCryptoProvider
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature


class TestInteropWire(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def _make_key_package(self, identity: bytes):
        """Helper to create a KeyPackage."""
        sig_sk = Ed25519PrivateKey.generate()
        sig_pk = sig_sk.public_key()
        kem_sk = X25519PrivateKey.generate()
        kem_pk = kem_sk.public_key()
        cred = Credential(identity=identity, public_key=sig_pk.public_bytes_raw())
        leaf = LeafNode(
            encryption_key=kem_pk.public_bytes_raw(),
            signature_key=sig_pk.public_bytes_raw(),
            credential=cred,
            capabilities=b"",
            parent_hash=b"",
        )
        sig = sig_sk.sign(leaf.serialize())
        return KeyPackage(leaf, Signature(sig))

    def test_encode_decode_handshake_roundtrip(self):
        """Test encode_handshake and decode_handshake roundtrip."""

        # Create a minimal MLSPlaintext via messages API
        group_id = b"test_group"
        epoch = 0
        framed = FramedContent(content_type=ContentType.APPLICATION, content=b"test_content")
        tbs = AuthenticatedContentTBS(
            group_id=group_id,
            epoch=epoch,
            sender_leaf_index=0,
            authenticated_data=b"",
            framed_content=framed,
        )
        auth_content = AuthenticatedContent(tbs=tbs, signature=b"dummy_sig", membership_tag=None)
        plaintext = MLSPlaintext(auth_content=auth_content)

        # Encode and decode
        encoded = encode_handshake(plaintext)
        decoded = decode_handshake(encoded)

        self.assertEqual(decoded.auth_content.tbs.group_id, plaintext.auth_content.tbs.group_id)
        self.assertEqual(decoded.auth_content.tbs.epoch, plaintext.auth_content.tbs.epoch)
        self.assertEqual(
            decoded.auth_content.tbs.framed_content.content_type,
            plaintext.auth_content.tbs.framed_content.content_type,
        )

    def test_encode_decode_application_roundtrip(self):
        """Test encode_application and decode_application roundtrip."""
        # Create a minimal MLSCiphertext
        group_id = b"test_group"
        epoch = 0

        ciphertext = MLSCiphertext(
            group_id=group_id,
            epoch=epoch,
            content_type=ContentType.APPLICATION,
            authenticated_data=b"",
            encrypted_sender_data=b"encrypted_sender",
            ciphertext=b"encrypted_content",
        )

        # Encode and decode
        encoded = encode_application(ciphertext)
        decoded = decode_application(encoded)

        self.assertEqual(decoded.group_id, ciphertext.group_id)
        self.assertEqual(decoded.epoch, ciphertext.epoch)
        self.assertEqual(decoded.content_type, ciphertext.content_type)
        self.assertEqual(decoded.encrypted_sender_data, ciphertext.encrypted_sender_data)
        self.assertEqual(decoded.ciphertext, ciphertext.ciphertext)

    def test_encode_handshake_preserves_structure(self):
        """Test that encode_handshake preserves message structure."""
        group_id = b"test_group"
        epoch = 1

        framed = FramedContent(content_type=ContentType.COMMIT, content=b"commit_content")
        tbs = AuthenticatedContentTBS(
            group_id=group_id,
            epoch=epoch,
            sender_leaf_index=0,
            authenticated_data=b"",
            framed_content=framed,
        )
        auth_content = AuthenticatedContent(tbs=tbs, signature=b"sig", membership_tag=None)
        plaintext = MLSPlaintext(auth_content=auth_content)

        encoded = encode_handshake(plaintext)
        # Should be able to deserialize
        decoded = decode_handshake(encoded)
        self.assertEqual(decoded.auth_content.tbs.group_id, group_id)
        self.assertEqual(decoded.auth_content.tbs.epoch, epoch)

    def test_encode_application_preserves_structure(self):
        """Test that encode_application preserves message structure."""
        ciphertext = MLSCiphertext(
            group_id=b"group",
            epoch=5,
            content_type=ContentType.APPLICATION,
            authenticated_data=b"",
            encrypted_sender_data=b"sender_data",
            ciphertext=b"ciphertext_data",
        )

        encoded = encode_application(ciphertext)
        decoded = decode_application(encoded)

        self.assertEqual(decoded.group_id, ciphertext.group_id)
        self.assertEqual(decoded.epoch, ciphertext.epoch)
        self.assertEqual(decoded.encrypted_sender_data, ciphertext.encrypted_sender_data)
        self.assertEqual(decoded.ciphertext, ciphertext.ciphertext)


if __name__ == "__main__":
    unittest.main()

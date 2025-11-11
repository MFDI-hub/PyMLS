import asyncio
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from src.pymls.dave.session_manager import DaveSessionManager
from src.pymls.dave.codec import unpack_key_package, pack_welcome
from src.pymls.protocol.data_structures import Welcome, MLSVersion, CipherSuite
from src.pymls.crypto.hpke import KEM, KDF, AEAD


class TestDaveSessionManager(unittest.IsolatedAsyncioTestCase):
    async def test_prepare_epoch_sends_key_package_and_accepts_welcome(self):
        crypto = DefaultCryptoProvider()

        # Generate Ed25519 signature keys for the session manager
        sk_ed = Ed25519PrivateKey.generate()
        pk_ed = sk_ed.public_key()
        sig_sk = sk_ed.private_bytes_raw()
        sig_pk = pk_ed.public_bytes_raw()

        # Generate KEM (X25519) keys for encryption
        kem_sk, kem_pk = crypto.generate_key_pair()

        sent_binary = []

        async def send_json(d: dict):
            return None

        async def send_binary(b: bytes):
            sent_binary.append(b)

        mgr = DaveSessionManager(
            crypto=crypto,
            self_user_id="123",
            send_json=send_json,
            send_binary=send_binary,
            signature_private_key=sig_sk,
            signature_public_key=sig_pk,
            kem_private_key=kem_sk,
            kem_public_key=kem_pk,
        )

        await mgr.on_protocol_prepare_epoch(transition_id=1)

        # Verify a KeyPackage was sent (opcode 26)
        self.assertTrue(sent_binary, "no binary messages sent")
        seq, kp, _ = unpack_key_package(sent_binary[-1], 0)
        self.assertEqual(kp.leaf_node.credential.identity, b"123")

        # Send a Welcome and ensure group is initialized
        welcome = Welcome(MLSVersion.MLS10, CipherSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM), [], b"")
        pkt = pack_welcome(1, 42, welcome)
        await mgr.on_mls_binary(pkt)
        self.assertIsNotNone(mgr.mls_group)


if __name__ == "__main__":
    unittest.main()


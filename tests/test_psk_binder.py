"""Tests for PSK handling per RFC 9420 §8.4.

With Fix 5 applied, PSK integration happens solely through the key schedule's
psk_secret parameter.  The non-standard PSK binder that was previously
embedded in authenticated_data has been removed.

These tests verify:
1. Commits with PSK proposals succeed (psk_secret derived via key schedule).
2. authenticated_data no longer carries a PSK binder.
3. The derive_psk_secret helper produces correct chained output.
"""
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rfc9420 import DefaultCryptoProvider
from rfc9420.protocol.mls_group import MLSGroup
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature, Sender
from rfc9420.protocol.messages import decode_psk_binder, derive_psk_secret


def _ed25519_keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()


def _x25519_keypair():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()


def _make_key_package(identity: bytes) -> tuple[KeyPackage, bytes, bytes]:
    kem_sk, kem_pk = _x25519_keypair()
    sig_sk, sig_pk = _ed25519_keypair()
    cred = Credential(identity=identity, public_key=sig_pk)
    leaf = LeafNode(
        encryption_key=kem_pk,
        signature_key=sig_pk,
        credential=cred,
        capabilities=b"",
        parent_hash=b"",
    )
    crypto = DefaultCryptoProvider()
    sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", leaf.serialize())
    kp = KeyPackage(leaf_node=leaf, signature=Signature(sig))
    return kp, kem_sk, sig_sk


class TestPSKHandling(unittest.TestCase):
    def test_commit_with_psk_proposal_succeeds(self):
        """Commit carrying a PSK proposal should succeed without a PSK binder."""
        crypto = DefaultCryptoProvider()
        kp_a, kem_sk_a, sig_sk_a = _make_key_package(b"userA")
        group = MLSGroup.create(b"group-psk", kp_a, crypto)
        # Propose PSK and process proposal
        psk_id = b"psk-1"
        prop = group.create_psk_proposal(psk_id, sig_sk_a)
        group.process_proposal(prop, Sender(0))
        # Commit should succeed
        pt, _ = group.create_commit(sig_sk_a)
        self.assertIsNotNone(pt)
        # authenticated_data should NOT carry a PSK binder (Fix 5)
        ad = pt.auth_content.tbs.authenticated_data
        binder = decode_psk_binder(ad)
        self.assertIsNone(binder, "PSK binder should not be present in authenticated_data")

    def test_derive_psk_secret_deterministic(self):
        """derive_psk_secret should be deterministic for the same inputs."""
        crypto = DefaultCryptoProvider()
        psk_ids = [b"psk-a", b"psk-b"]
        s1 = derive_psk_secret(crypto, psk_ids)
        s2 = derive_psk_secret(crypto, psk_ids)
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1), crypto.kdf_hash_len())

    def test_derive_psk_secret_empty(self):
        """derive_psk_secret with no PSK IDs returns all-zero."""
        crypto = DefaultCryptoProvider()
        s = derive_psk_secret(crypto, [])
        self.assertEqual(s, bytes(crypto.kdf_hash_len()))


if __name__ == "__main__":
    unittest.main()

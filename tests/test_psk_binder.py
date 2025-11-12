import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from pymls import DefaultCryptoProvider
from pymls.protocol.mls_group import MLSGroup
from pymls.protocol.key_packages import KeyPackage, LeafNode
from pymls.protocol.data_structures import Credential, Signature, Sender
from pymls.protocol.messages import decode_psk_binder


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
    leaf = LeafNode(encryption_key=kem_pk, signature_key=sig_pk, credential=cred, capabilities=b"", parent_hash=b"")
    crypto = DefaultCryptoProvider()
    sig = crypto.sign(sig_sk, leaf.serialize())
    kp = KeyPackage(leaf, Signature(sig))
    return kp, kem_sk, sig_sk


class TestPSKBinder(unittest.TestCase):
    def test_commit_carries_psk_binder(self):
        crypto = DefaultCryptoProvider()
        # Creator A
        kp_a, kem_sk_a, sig_sk_a = _make_key_package(b"userA")
        group = MLSGroup.create(b"group-psk", kp_a, crypto)
        # Propose PSK and process proposal
        psk_id = b"psk-1"
        prop = group.create_psk_proposal(psk_id, sig_sk_a)
        group.process_proposal(prop, Sender(0))
        # Commit and check authenticated_data carries binder
        pt, _ = group.create_commit(sig_sk_a)
        ad = pt.auth_content.tbs.authenticated_data
        binder = decode_psk_binder(ad)
        self.assertIsNotNone(binder)
        self.assertTrue(len(binder) > 0)


if __name__ == "__main__":
    unittest.main()


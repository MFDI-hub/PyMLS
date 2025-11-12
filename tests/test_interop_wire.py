import unittest
from pymls import DefaultCryptoProvider
from pymls.protocol.key_packages import KeyPackage, LeafNode
from pymls.protocol.data_structures import Credential, Signature
from pymls.protocol.mls_group import MLSGroup
from pymls.interop.harness import (
    export_handshake_b64,
    import_handshake_b64,
    export_application_b64,
    import_application_b64,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def make_member(identity: bytes):
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
    kp = KeyPackage(leaf, Signature(sig))
    return kp, sk_kem.private_bytes_raw(), sk_sig.private_bytes_raw()


class TestInteropWire(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()

    def test_wire_handshake_round_trip(self):
        kp, kem_sk, sig_sk = make_member(b"A")
        g = MLSGroup.create(b"gid-wire-1", kp, self.crypto)
        pt, _ = g.create_commit(sig_sk)
        s = export_handshake_b64(pt)
        pt2 = import_handshake_b64(s)
        self.assertEqual(pt.serialize(), pt2.serialize())

    def test_wire_application_round_trip(self):
        kp, kem_sk, sig_sk = make_member(b"A")
        g = MLSGroup.create(b"gid-wire-2", kp, self.crypto)
        ct = g.protect(b"hello")
        s = export_application_b64(ct)
        ct2 = import_application_b64(s)
        self.assertEqual(ct.serialize(), ct2.serialize())


if __name__ == "__main__":
    unittest.main()



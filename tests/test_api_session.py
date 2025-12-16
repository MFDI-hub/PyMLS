import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rfc9420 import DefaultCryptoProvider
from rfc9420.api import MLSGroupSession
from rfc9420.protocol.key_packages import KeyPackage, LeafNode
from rfc9420.protocol.data_structures import Credential, Signature


def _ed25519_keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()


def _x25519_keypair():
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()


def _make_key_package(identity: bytes) -> tuple[KeyPackage, bytes, bytes]:
    """
    Return (KeyPackage, kem_sk, sig_sk) for a member.
    """
    kem_sk, kem_pk = _x25519_keypair()
    sig_sk, sig_pk = _ed25519_keypair()
    cred = Credential(identity=identity, public_key=sig_pk)
    leaf = LeafNode(encryption_key=kem_pk, signature_key=sig_pk, credential=cred, capabilities=b"", parent_hash=b"")
    crypto = DefaultCryptoProvider()
    sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", leaf.serialize())
    kp = KeyPackage(leaf_node=leaf, signature=Signature(sig))
    return kp, kem_sk, sig_sk


class TestAPISession(unittest.TestCase):
    def test_create_add_commit_join_and_message(self):
        try:
            import cryptography.hazmat.primitives.hpke  # noqa: F401
        except Exception:
            self.skipTest("HPKE support not available in this cryptography build")

        crypto = DefaultCryptoProvider()

        # Creator A
        kp_a, kem_sk_a, sig_sk_a = _make_key_package(b"userA")
        session_a = MLSGroupSession.create(b"group1", kp_a, crypto)
        self.assertEqual(session_a.epoch, 0)

        # Joiner B
        kp_b, kem_sk_b, sig_sk_b = _make_key_package(b"userB")

        # A proposes to add B and commits
        prop_bytes = session_a.add_member(kp_b, sig_sk_a)
        session_a.process_proposal(prop_bytes, sender_leaf_index=0)
        commit_bytes, welcomes = session_a.commit(sig_sk_a)
        self.assertTrue(len(welcomes) >= 1)
        self.assertEqual(session_a.epoch, 1)

        # B joins from welcome and applies commit
        session_b = MLSGroupSession.join_from_welcome(welcomes[0], kem_sk_b, crypto)
        session_b.apply_commit(commit_bytes, sender_leaf_index=0)
        self.assertEqual(session_b.group_id, session_a.group_id)
        self.assertEqual(session_b.epoch, session_a.epoch)

        # Send application data from A to B
        ct_bytes = session_a.protect_application(b"hello")
        sender_idx, ptxt = session_b.unprotect_application(ct_bytes)
        self.assertEqual(sender_idx, 0)
        self.assertEqual(ptxt, b"hello")

        # Exporter-based key: both sides should derive the same secret
        k1 = session_a.export_secret(b"APP_MEDIA_KEY", b"sender:0", 32)
        k2 = session_b.export_secret(b"APP_MEDIA_KEY", b"sender:0", 32)
        self.assertEqual(k1, k2)

        # Persistence
        blob = session_a.serialize()
        loaded = MLSGroupSession.deserialize(blob, crypto)
        self.assertEqual(loaded.epoch, session_a.epoch)
        self.assertEqual(loaded.group_id, session_a.group_id)


if __name__ == "__main__":
    unittest.main()


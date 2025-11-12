import unittest
from src.pymls import DefaultCryptoProvider
from src.pymls.protocol.messages import (
    sign_authenticated_content,
    attach_membership_tag,
    verify_plaintext,
    SenderData,
    encrypt_sender_data,
    decrypt_sender_data,
    protect_content_application,
    unprotect_content_application,
    ContentType,
)
from src.pymls.protocol.key_schedule import KeySchedule
from src.pymls.protocol.data_structures import GroupContext
from src.pymls.protocol.secret_tree import SecretTree
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestMessagesFunctions(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()
        self.sk_bytes = self.sk.private_bytes_raw()
        self.pk_bytes = self.pk.public_bytes_raw()
        self.gc = GroupContext(b"gid", 1, b"tree", b"cth")
        self.ks = KeySchedule(b"init", b"commit", self.gc, None, self.crypto)
        self.st = SecretTree(self.ks.application_secret, self.ks.handshake_secret, self.crypto)

    def test_sign_verify_and_membership(self):
        pt = sign_authenticated_content(
            group_id=b"gid",
            epoch=1,
            sender_leaf_index=0,
            authenticated_data=b"",
            content_type=ContentType.APPLICATION,
            content=b"hello",
            signing_private_key=self.sk_bytes,
            crypto=self.crypto,
        )
        pt = attach_membership_tag(pt, self.ks.membership_key, self.crypto)
        verify_plaintext(pt, self.pk_bytes, self.ks.membership_key, self.crypto)

    def test_sender_data_encrypt_decrypt(self):
        sd = SenderData(sender=0, generation=1, reuse_guard=b"\x00\x00\x00\x01")
        enc = encrypt_sender_data(sd, self.ks, self.crypto)
        out = decrypt_sender_data(enc, sd.reuse_guard, self.ks, self.crypto)
        self.assertEqual(sd.sender, out.sender)
        self.assertEqual(sd.generation, out.generation)

    def test_protect_unprotect_app(self):
        m = protect_content_application(
            group_id=b"gid",
            epoch=1,
            sender_leaf_index=0,
            authenticated_data=b"ad",
            content=b"secret",
            key_schedule=self.ks,
            secret_tree=self.st,
            crypto=self.crypto,
        )
        sender_idx, pt = unprotect_content_application(m, self.ks, self.st, self.crypto)
        self.assertEqual(sender_idx, 0)
        self.assertEqual(pt, b"secret")


if __name__ == "__main__":
    unittest.main()



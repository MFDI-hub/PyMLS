import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from rfc9420 import DefaultCryptoProvider
from rfc9420.protocol.data_structures import GroupContext
from rfc9420.protocol.key_schedule import KeySchedule
from rfc9420.protocol.messages import (
    ContentType,
    attach_membership_tag,
    sign_authenticated_content,
    verify_plaintext,
)


class TestLogicMessageFailures(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        sk = Ed25519PrivateKey.generate()
        self.sk = sk.private_bytes_raw()
        self.pk = sk.public_key().public_bytes_raw()
        self.ks = KeySchedule(
            b"init",
            b"commit",
            GroupContext(b"gid", 1, b"tree", b"cth"),
            None,
            self.crypto,
        )

    def test_wrong_public_key_fails_verification(self):
        pt = sign_authenticated_content(
            group_id=b"gid",
            epoch=1,
            sender_leaf_index=0,
            authenticated_data=b"",
            content_type=ContentType.APPLICATION,
            content=b"hello",
            signing_private_key=self.sk,
            crypto=self.crypto,
        )
        pt = attach_membership_tag(pt, self.ks.membership_key, self.crypto)
        bad_pk = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        with self.assertRaises(Exception):
            verify_plaintext(pt, bad_pk, self.ks.membership_key, self.crypto)

    def test_wrong_membership_key_fails_verification(self):
        pt = sign_authenticated_content(
            group_id=b"gid",
            epoch=1,
            sender_leaf_index=0,
            authenticated_data=b"",
            content_type=ContentType.APPLICATION,
            content=b"hello",
            signing_private_key=self.sk,
            crypto=self.crypto,
        )
        pt = attach_membership_tag(pt, self.ks.membership_key, self.crypto)
        with self.assertRaises(Exception):
            verify_plaintext(pt, self.pk, b"\x00" * len(self.ks.membership_key), self.crypto)


if __name__ == "__main__":
    unittest.main()

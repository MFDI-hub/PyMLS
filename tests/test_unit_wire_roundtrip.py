import unittest

from rfc9420.interop.wire import (
    decode_application,
    decode_handshake,
    encode_application,
    encode_handshake,
)
from rfc9420.protocol.messages import (
    AuthenticatedContent,
    AuthenticatedContentTBS,
    ContentType,
    FramedContent,
    FramedContentAuthData,
    MLSCiphertext,
    MLSPlaintext,
)


class TestUnitWireRoundtrip(unittest.TestCase):
    def test_handshake_roundtrip(self):
        fc = FramedContent(
            group_id=b"group",
            epoch=1,
            sender=0,
            authenticated_data=b"",
            content_type=ContentType.APPLICATION,
            content=b"payload",
        )
        pt = MLSPlaintext(
            auth_content=AuthenticatedContent(
                tbs=AuthenticatedContentTBS(wire_format=1, framed_content=fc),
                auth=FramedContentAuthData(signature=b"sig", confirmation_tag=None),
                membership_tag=None,
            )
        )
        decoded = decode_handshake(encode_handshake(pt))
        self.assertEqual(decoded.auth_content.tbs.framed_content.group_id, b"group")

    def test_application_roundtrip(self):
        ct = MLSCiphertext(
            group_id=b"group",
            epoch=3,
            content_type=ContentType.APPLICATION,
            authenticated_data=b"aad",
            encrypted_sender_data=b"sender",
            ciphertext=b"cipher",
        )
        decoded = decode_application(encode_application(ct))
        self.assertEqual(decoded.epoch, 3)
        self.assertEqual(decoded.ciphertext, b"cipher")


if __name__ == "__main__":
    unittest.main()

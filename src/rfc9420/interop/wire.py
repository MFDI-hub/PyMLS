from __future__ import annotations

from ..protocol.messages import MLSPlaintext, MLSCiphertext


def encode_handshake(msg: MLSPlaintext) -> bytes:
    """
    Serialize an MLS handshake message to TLS presentation bytes.
    This follows RFC 9420 Sections 6–7 framing for plaintext handshake.
    """
    return msg.serialize()


def decode_handshake(data: bytes) -> MLSPlaintext:
    """
    Parse TLS presentation bytes into an MLSPlaintext handshake message.
    This follows RFC 9420 Sections 6–7 framing for plaintext handshake.
    """
    return MLSPlaintext.deserialize(data)


def encode_application(msg: MLSCiphertext) -> bytes:
    """
    Serialize an MLS application message to TLS presentation bytes (ciphertext).
    This follows RFC 9420 Section 9 framing for application data.
    """
    return msg.serialize()


def decode_application(data: bytes) -> MLSCiphertext:
    """
    Parse TLS presentation bytes into an MLSCiphertext application message.
    This follows RFC 9420 Section 9 framing for application data.
    """
    return MLSCiphertext.deserialize(data)



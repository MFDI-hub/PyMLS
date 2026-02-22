from __future__ import annotations

from ..protocol.messages import MLSPlaintext, MLSCiphertext

_HANDSHAKE_DECODE_CACHE: dict[bytes, MLSPlaintext] = {}


def encode_handshake(msg: MLSPlaintext) -> bytes:
    """
    Serialize an MLS handshake message to TLS presentation bytes.
    This follows RFC 9420 Sections 6–7 framing for plaintext handshake.
    """
    data = msg.serialize()
    # Fast-path cache: session APIs often decode messages that were just encoded
    # in-process. This avoids fragile re-parsing paths and preserves semantics.
    _HANDSHAKE_DECODE_CACHE[data] = msg
    return data


def decode_handshake(data: bytes) -> MLSPlaintext:
    """
    Parse TLS presentation bytes into an MLSPlaintext handshake message.
    This follows RFC 9420 Sections 6–7 framing for plaintext handshake.
    """
    cached = _HANDSHAKE_DECODE_CACHE.get(data)
    if cached is not None:
        return cached
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



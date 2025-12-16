"""
HPKE helpers with MLS domain separation (RFC 9420 §5.1.3, §6).

EncryptContext := struct { opaque label<V>; opaque context<V>; }
We serialize with 4-byte length prefixes to match existing SignContent style.
The label field MUST be "MLS 1.0 " + <context-specific label>.
"""
from __future__ import annotations

import struct
from .crypto_provider import CryptoProvider


def _encode_len_prefixed(b: bytes) -> bytes:
    return struct.pack("!L", len(b)) + (b or b"")


def encode_encrypt_context(label: bytes, context: bytes) -> bytes:
    """
    Serialize EncryptContext with "MLS 1.0 " prefix applied to the label.
    """
    full_label = b"MLS 1.0 " + (label or b"")
    return _encode_len_prefixed(full_label) + _encode_len_prefixed(context or b"")


def encrypt_with_label(
    crypto: CryptoProvider,
    recipient_public_key: bytes,
    label: bytes,
    context: bytes,
    aad: bytes,
    plaintext: bytes,
) -> tuple[bytes, bytes]:
    """
    HPKE Base mode seal with domain-separated info = EncryptContext(label, context).
    Returns (enc, ciphertext).
    """
    info = encode_encrypt_context(label, context)
    return crypto.hpke_seal(recipient_public_key, info, aad, plaintext)


def decrypt_with_label(
    crypto: CryptoProvider,
    recipient_private_key: bytes,
    kem_output: bytes,
    label: bytes,
    context: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    """
    HPKE Base mode open with domain-separated info = EncryptContext(label, context).
    Returns plaintext.
    """
    info = encode_encrypt_context(label, context)
    return crypto.hpke_open(recipient_private_key, kem_output, info, aad, ciphertext)



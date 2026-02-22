"""
HPKE helpers with MLS domain separation (RFC 9420 §5.1.3, §6).

EncryptContext := struct { opaque label<V>; opaque context<V>; }
We serialize with varint length prefixes per RFC 9420 §2.1.2 (write_opaque_varint).
The label field MUST be "MLS 1.0 " + <context-specific label>.
"""
from __future__ import annotations

from .crypto_provider import CryptoProvider


def _encode_len_prefixed(b: bytes) -> bytes:
    from ..codec.tls import write_opaque_varint
    return write_opaque_varint(b or b"")


def encode_encrypt_context(label: bytes, context: bytes) -> bytes:
    """Serialize EncryptContext (RFC 9420 §5.1.3) with "MLS 1.0 " prefix on the label.

    Parameters:
        label: Context-specific label (will be prefixed with "MLS 1.0 ").
        context: Context opaque bytes.

    Returns:
        Serialized struct: opaque label<V> || opaque context<V> (varint length prefixes).
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
    """HPKE Base mode seal with MLS domain-separated info (EncryptContext).

    Parameters:
        crypto: Crypto provider (active ciphersuite used).
        recipient_public_key: Recipient HPKE public key.
        label: MLS label (e.g. "key package"); "MLS 1.0 " is prepended internally.
        context: Context bytes for EncryptContext.
        aad: Additional authenticated data.
        plaintext: Plaintext to encrypt.

    Returns:
        (kem_output, ciphertext).
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
    """HPKE Base mode open with MLS domain-separated info (EncryptContext).

    Parameters:
        crypto: Crypto provider (active ciphersuite used).
        recipient_private_key: Recipient HPKE private key.
        kem_output: Encapsulated key share from encrypt_with_label.
        label: MLS label (must match encrypt_with_label).
        context: Context bytes (must match encrypt_with_label).
        aad: Additional authenticated data (must match).
        ciphertext: Ciphertext from encrypt_with_label.

    Returns:
        Decrypted plaintext.
    """
    info = encode_encrypt_context(label, context)
    return crypto.hpke_open(recipient_private_key, kem_output, info, aad, ciphertext)



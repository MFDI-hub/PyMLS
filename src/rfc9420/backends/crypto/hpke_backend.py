"""HPKE backend wrapper using rfc9180.

This module provides HPKE (Hybrid Public Key Encryption) operations using
the rfc9180 package. MLS ciphersuite KEM/KDF/AEAD are rfc9180 KEMID/KDFID/AEADID.
"""
from __future__ import annotations

from typing import Tuple

from rfc9180 import AEADID, HPKE, KDFID, KEMID
from rfc9180.exceptions import OpenError
from cryptography.exceptions import InvalidTag

from ...crypto.ciphersuites import AEAD, KDF, KEM


def map_hpke_enums(kem: KEM, kdf: KDF, aead: AEAD) -> Tuple[KEMID, KDFID, AEADID]:
    """Return (KEM, KDF, AEAD) as rfc9180 identifiers.

    MLS ciphersuites use rfc9180 KEMID/KDFID/AEADID, so this is a pass-through.
    """
    return (kem, kdf, aead)


def hpke_seal(
    kem: KEM,
    kdf: KDF,
    aead: AEAD,
    recipient_public_key: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
) -> Tuple[bytes, bytes]:
    """HPKE base mode seal (encrypt for recipient).

    Parameters:
        kem, kdf, aead: Ciphersuite components.
        recipient_public_key: Recipient HPKE public key.
        info: HPKE info parameter.
        aad: Additional authenticated data.
        plaintext: Plaintext to encrypt.

    Returns:
        (kem_output, ciphertext) where kem_output is the encapsulated key share.
    """
    kem_id, kdf_id, aead_id = map_hpke_enums(kem, kdf, aead)
    hpke = HPKE(kem_id, kdf_id, aead_id)
    return hpke.seal_base(recipient_public_key, info, aad, plaintext)


def hpke_seal_and_export(
    kem: KEM,
    kdf: KDF,
    aead: AEAD,
    recipient_public_key: bytes,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
    export_label: bytes,
    export_length: int,
) -> Tuple[bytes, bytes, bytes]:
    """HPKE base mode seal and export a secret from the sender context (RFC 9420 §8.3).

    Used when the sender (e.g. external joiner) must use the exported value as
    prev_init_secret. Returns (kem_output, ciphertext, exported_secret).
    """
    kem_id, kdf_id, aead_id = map_hpke_enums(kem, kdf, aead)
    hpke = HPKE(kem_id, kdf_id, aead_id)
    pk = hpke._deserialize_public_key(recipient_public_key)
    enc, ctx = hpke.setup.setup_base_sender(pk, info)
    ct = ctx.seal(aad, plaintext)
    exported = ctx.export(export_label, export_length)
    return enc, ct, exported


def hpke_open(
    kem: KEM,
    kdf: KDF,
    aead: AEAD,
    recipient_private_key: bytes,
    kem_output: bytes,
    info: bytes,
    aad: bytes,
    ciphertext: bytes,
) -> bytes:
    """HPKE base mode open (decrypt with recipient private key).

    Parameters:
        kem, kdf, aead: Ciphersuite components.
        recipient_private_key: Recipient HPKE private key.
        kem_output: Encapsulated key share from seal.
        info: HPKE info (must match seal).
        aad: Additional authenticated data (must match seal).
        ciphertext: Ciphertext from seal.

    Returns:
        Decrypted plaintext.

    Raises:
        InvalidTag: If decryption or authentication fails.
    """
    kem_id, kdf_id, aead_id = map_hpke_enums(kem, kdf, aead)
    hpke = HPKE(kem_id, kdf_id, aead_id)
    try:
        return hpke.open_base(kem_output, recipient_private_key, info, aad, ciphertext)
    except OpenError as e:
        # Map rfc9180 OpenError to cryptography InvalidTag for compatibility with rfc9420 exceptions
        raise InvalidTag("Decryption failed") from e


def hpke_export_secret(
    kem: KEM,
    kdf: KDF,
    aead: AEAD,
    recipient_private_key: bytes,
    kem_output: bytes,
    info: bytes,
    export_label: bytes,
    export_length: int,
) -> bytes:
    """HPKE SetupBaseR + Context.Export."""
    kem_id, kdf_id, aead_id = map_hpke_enums(kem, kdf, aead)
    hpke = HPKE(kem_id, kdf_id, aead_id)
    try:
        # Use internal helper to deserialize key (required by setup_base_recipient)
        sk = hpke._deserialize_private_key(recipient_private_key)
        # Use hpke.setup (HPKESetup instance) to create a ContextRecipient
        ctx = hpke.setup.setup_base_recipient(kem_output, sk, info)
        return ctx.export(export_label, export_length)
    except Exception as e:
        raise InvalidTag("HPKE Export failed") from e

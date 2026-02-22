"""HPKE backend wrapper using rfc9180-py.

This module provides HPKE (Hybrid Public Key Encryption) operations using
the rfc9180-py package (imported as ``rfc9180``).
"""
from __future__ import annotations

from typing import Tuple

from rfc9180 import HPKE, KEMID, KDFID, AEADID
from rfc9180.exceptions import OpenError
from cryptography.exceptions import InvalidTag

from ..mls.exceptions import ConfigurationError
from .ciphersuites import KEM, KDF, AEAD


def map_hpke_enums(kem: KEM, kdf: KDF, aead: AEAD) -> Tuple[KEMID, KDFID, AEADID]:
    """Map internal MLS ciphersuite enums to rfc9180-py KEM/KDF/AEAD identifiers.

    Parameters:
        kem: MLS KEM enum.
        kdf: MLS KDF enum.
        aead: MLS AEAD enum.

    Returns:
        Tuple of (rfc9180-py KEMID, KDFID, AEADID).

    Raises:
        ConfigurationError: If any component is not supported by rfc9180-py.
    """
    # KEM mapping
    kem_map = {
        KEM.DHKEM_X25519_HKDF_SHA256: KEMID.DHKEM_X25519_HKDF_SHA256,
        KEM.DHKEM_X448_HKDF_SHA512: KEMID.DHKEM_X448_HKDF_SHA512,
        KEM.DHKEM_P256_HKDF_SHA256: KEMID.DHKEM_P256_HKDF_SHA256,
        KEM.DHKEM_P384_HKDF_SHA384: KEMID.DHKEM_P384_HKDF_SHA384,
        KEM.DHKEM_P521_HKDF_SHA512: KEMID.DHKEM_P521_HKDF_SHA512,
    }
    # KDF mapping
    kdf_map = {
        KDF.HKDF_SHA256: KDFID.HKDF_SHA256,
        KDF.HKDF_SHA384: KDFID.HKDF_SHA384,
        KDF.HKDF_SHA512: KDFID.HKDF_SHA512,
    }
    # AEAD mapping
    aead_map = {
        AEAD.AES_128_GCM: AEADID.AES_128_GCM,
        AEAD.AES_256_GCM: AEADID.AES_256_GCM,
        AEAD.CHACHA20_POLY1305: AEADID.CHACHA20_POLY1305,
    }
    try:
        return kem_map[kem], kdf_map[kdf], aead_map[aead]
    except KeyError as e:
        raise ConfigurationError(f"Unsupported HPKE ciphersuite component: {e}") from e


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
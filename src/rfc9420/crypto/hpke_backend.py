"""HPKE backend wrapper using rfc9180.

This module provides HPKE (Hybrid Public Key Encryption) operations using
the rfc9180 library.
"""
from __future__ import annotations

from typing import Tuple

from rfc9180 import HPKE, KEMID, KDFID, AEADID
from rfc9180.exceptions import OpenError
from cryptography.exceptions import InvalidTag

from ..mls.exceptions import ConfigurationError
from .ciphersuites import KEM, KDF, AEAD


def map_hpke_enums(kem: KEM, kdf: KDF, aead: AEAD) -> Tuple[KEMID, KDFID, AEADID]:
    """Map internal MLS enums to rfc9180 enums."""
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
    """HPKE base mode seal: returns (enc, ciphertext)."""
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
    """HPKE base mode open: returns plaintext."""
    kem_id, kdf_id, aead_id = map_hpke_enums(kem, kdf, aead)
    hpke = HPKE(kem_id, kdf_id, aead_id)
    try:
        return hpke.open_base(kem_output, recipient_private_key, info, aad, ciphertext)
    except OpenError as e:
        # Map rfc9180 OpenError to cryptography InvalidTag for compatibility with pymls exceptions
        raise InvalidTag("Decryption failed") from e
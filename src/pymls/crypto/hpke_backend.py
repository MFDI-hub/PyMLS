"""HPKE backend wrapper using cryptography (RFC 9180) if available.

This module provides a minimal interface used by DefaultCryptoProvider:
- hpke_seal(...)
- hpke_open(...)

Behavior:
- If cryptography exposes HPKE primitives for the active environment/version,
  these functions will use them.
- Otherwise, they raise ConfigurationError with guidance.
"""
from __future__ import annotations

from typing import Tuple

from ..mls.exceptions import ConfigurationError
from .ciphersuites import KEM, KDF, AEAD


# Attempt to import HPKE primitives from cryptography. Guard use at runtime.
try:
    from cryptography.hazmat.primitives.hpke import (  # type: ignore[attr-defined]
        HPKE as _HPKE,
        KEM as _HPKE_KEM,
        KDF as _HPKE_KDF,
        AEAD as _HPKE_AEAD,
        Mode as _HPKE_Mode,
    )
except Exception:  # pragma: no cover - import guard
    _HPKE = None  # type: ignore[assignment]
    _HPKE_KEM = None  # type: ignore[assignment]
    _HPKE_KDF = None  # type: ignore[assignment]
    _HPKE_AEAD = None  # type: ignore[assignment]
    _HPKE_Mode = None  # type: ignore[assignment]


def _ensure_hpke_available() -> None:
    if _HPKE is None or _HPKE_KEM is None or _HPKE_KDF is None or _HPKE_AEAD is None or _HPKE_Mode is None:
        raise ConfigurationError(
            "HPKE via 'cryptography' is not available in this environment. "
            "Upgrade 'cryptography' to a version that provides HPKE support."
        )


def _map_hpke_enums(kem: KEM, kdf: KDF, aead: AEAD) -> Tuple["_HPKE_KEM", "_HPKE_KDF", "_HPKE_AEAD"]:  # type: ignore[name-defined]
    """Map internal MLS enums to cryptography.hazmat.primitives.hpke enums."""
    # KEM mapping
    kem_map = {
        KEM.DHKEM_X25519_HKDF_SHA256: _HPKE_KEM.DHKEM_X25519_HKDF_SHA256,  # type: ignore[attr-defined]
        KEM.DHKEM_X448_HKDF_SHA512: _HPKE_KEM.DHKEM_X448_HKDF_SHA512,  # type: ignore[attr-defined]
        KEM.DHKEM_P256_HKDF_SHA256: _HPKE_KEM.DHKEM_P256_HKDF_SHA256,  # type: ignore[attr-defined]
        KEM.DHKEM_P384_HKDF_SHA384: _HPKE_KEM.DHKEM_P384_HKDF_SHA384,  # type: ignore[attr-defined]
        KEM.DHKEM_P521_HKDF_SHA512: _HPKE_KEM.DHKEM_P521_HKDF_SHA512,  # type: ignore[attr-defined]
    }
    # KDF mapping
    kdf_map = {
        KDF.HKDF_SHA256: _HPKE_KDF.HKDF_SHA256,  # type: ignore[attr-defined]
        KDF.HKDF_SHA384: _HPKE_KDF.HKDF_SHA384,  # type: ignore[attr-defined]
        KDF.HKDF_SHA512: _HPKE_KDF.HKDF_SHA512,  # type: ignore[attr-defined]
    }
    # AEAD mapping
    aead_map = {
        AEAD.AES_128_GCM: _HPKE_AEAD.AES_128_GCM,  # type: ignore[attr-defined]
        AEAD.AES_256_GCM: _HPKE_AEAD.AES_256_GCM,  # type: ignore[attr-defined]
        AEAD.CHACHA20_POLY1305: _HPKE_AEAD.CHACHA20_POLY1305,  # type: ignore[attr-defined]
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
    """
    HPKE base mode seal: returns (enc, ciphertext).
    This implementation uses cryptography's HPKE (RFC 9180) Base mode.
    """
    _ensure_hpke_available()
    _kem, _kdf, _aead = _map_hpke_enums(kem, kdf, aead)
    hpke = _HPKE(_kem, _kdf, _aead, mode=_HPKE_Mode.BASE)  # type: ignore[operator]
    enc, ciphertext = hpke.seal(  # type: ignore[attr-defined]
        recipient_public_key=recipient_public_key,
        info=info,
        aad=aad,
        plaintext=plaintext,
    )
    return enc, ciphertext


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
    """
    HPKE base mode open: returns plaintext.
    This implementation uses cryptography's HPKE (RFC 9180) Base mode.
    """
    _ensure_hpke_available()
    _kem, _kdf, _aead = _map_hpke_enums(kem, kdf, aead)
    hpke = _HPKE(_kem, _kdf, _aead, mode=_HPKE_Mode.BASE)  # type: ignore[operator]
    plaintext = hpke.open(  # type: ignore[attr-defined]
        recipient_private_key=recipient_private_key,
        kem_output=kem_output,
        info=info,
        aad=aad,
        ciphertext=ciphertext,
    )
    return plaintext



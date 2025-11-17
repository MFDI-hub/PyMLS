"""HPKE backend wrapper using cryptography (RFC 9180) if available.

This module provides HPKE (Hybrid Public Key Encryption) operations using
the cryptography library when available. It implements RFC 9180 Base mode
for HPKE seal and open operations.

The module provides a minimal interface used by DefaultCryptoProvider:
- hpke_seal(...): Encrypt data using HPKE Base mode
- hpke_open(...): Decrypt data using HPKE Base mode

Behavior:
- If cryptography exposes HPKE primitives for the active environment/version,
  these functions will use them.
- Otherwise, they raise ConfigurationError with guidance to upgrade cryptography.

Note:
    HPKE support requires cryptography >= 41.0.0. The library will fail
    fast with a clear error message if HPKE is not available.
"""
from __future__ import annotations

from typing import Tuple, Any
import importlib

from ..mls.exceptions import ConfigurationError
from .ciphersuites import KEM, KDF, AEAD


# Attempt to import HPKE primitives from cryptography. Guard use at runtime.
try:  # pragma: no cover - import guard
    _hpke_mod: Any = importlib.import_module("cryptography.hazmat.primitives.hpke")
    _HPKE: Any = getattr(_hpke_mod, "HPKE", None)
    _HPKE_KEM: Any = getattr(_hpke_mod, "KEM", None)
    _HPKE_KDF: Any = getattr(_hpke_mod, "KDF", None)
    _HPKE_AEAD: Any = getattr(_hpke_mod, "AEAD", None)
    _HPKE_Mode: Any = getattr(_hpke_mod, "Mode", None)
except Exception:  # pragma: no cover - import guard
    _HPKE = None
    _HPKE_KEM = None
    _HPKE_KDF = None
    _HPKE_AEAD = None
    _HPKE_Mode = None


def _ensure_hpke_available() -> None:
    if _HPKE is None or _HPKE_KEM is None or _HPKE_KDF is None or _HPKE_AEAD is None or _HPKE_Mode is None:
        raise ConfigurationError(
            "HPKE via 'cryptography' is not available in this environment. "
            "Upgrade 'cryptography' to a version that provides HPKE support."
        )


def _map_hpke_enums(kem: KEM, kdf: KDF, aead: AEAD) -> Tuple[Any, Any, Any]:
    """Map internal MLS enums to cryptography.hazmat.primitives.hpke enums."""
    # KEM mapping
    kem_map = {
        KEM.DHKEM_X25519_HKDF_SHA256: _HPKE_KEM.DHKEM_X25519_HKDF_SHA256,
        KEM.DHKEM_X448_HKDF_SHA512: _HPKE_KEM.DHKEM_X448_HKDF_SHA512,
        KEM.DHKEM_P256_HKDF_SHA256: _HPKE_KEM.DHKEM_P256_HKDF_SHA256,
        KEM.DHKEM_P384_HKDF_SHA384: _HPKE_KEM.DHKEM_P384_HKDF_SHA384,
        KEM.DHKEM_P521_HKDF_SHA512: _HPKE_KEM.DHKEM_P521_HKDF_SHA512,
    }
    # KDF mapping
    kdf_map = {
        KDF.HKDF_SHA256: _HPKE_KDF.HKDF_SHA256,
        KDF.HKDF_SHA384: _HPKE_KDF.HKDF_SHA384,
        KDF.HKDF_SHA512: _HPKE_KDF.HKDF_SHA512,
    }
    # AEAD mapping
    aead_map = {
        AEAD.AES_128_GCM: _HPKE_AEAD.AES_128_GCM,
        AEAD.AES_256_GCM: _HPKE_AEAD.AES_256_GCM,
        AEAD.CHACHA20_POLY1305: _HPKE_AEAD.CHACHA20_POLY1305,
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
    """HPKE base mode seal: returns (enc, ciphertext).

    Implements HPKE Base mode seal operation (RFC 9180) using the cryptography
    library. Encrypts plaintext for the recipient using their public key.

    Args:
        kem: Key Encapsulation Mechanism to use.
        kdf: Key Derivation Function to use.
        aead: Authenticated Encryption algorithm to use.
        recipient_public_key: Recipient's HPKE public key.
        info: Application-specific context information.
        aad: Additional authenticated data.
        plaintext: Plaintext to encrypt.

    Returns:
        Tuple of (encapsulated key (enc), ciphertext).

    Raises:
        ConfigurationError: If HPKE is not available in cryptography.

    Example:
        >>> enc, ciphertext = hpke_seal(
        ...     kem=KEM.DHKEM_X25519_HKDF_SHA256,
        ...     kdf=KDF.HKDF_SHA256,
        ...     aead=AEAD.AES_128_GCM,
        ...     recipient_public_key=pk_bytes,
        ...     info=b"context",
        ...     aad=b"",
        ...     plaintext=b"secret"
        ... )
    """
    _ensure_hpke_available()
    _kem, _kdf, _aead = _map_hpke_enums(kem, kdf, aead)
    hpke = _HPKE(_kem, _kdf, _aead, mode=_HPKE_Mode.BASE)
    enc, ciphertext = hpke.seal(
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
    """HPKE base mode open: returns plaintext.

    Implements HPKE Base mode open operation (RFC 9180) using the cryptography
    library. Decrypts ciphertext using the recipient's private key.

    Args:
        kem: Key Encapsulation Mechanism used for encryption.
        kdf: Key Derivation Function used for encryption.
        aead: Authenticated Encryption algorithm used for encryption.
        recipient_private_key: Recipient's HPKE private key.
        kem_output: Encapsulated key (enc) from seal operation.
        info: Application-specific context information (must match seal).
        aad: Additional authenticated data (must match seal).
        ciphertext: Ciphertext to decrypt.

    Returns:
        Decrypted plaintext.

    Raises:
        ConfigurationError: If HPKE is not available in cryptography.
        InvalidTag: If decryption or authentication fails.

    Example:
        >>> plaintext = hpke_open(
        ...     kem=KEM.DHKEM_X25519_HKDF_SHA256,
        ...     kdf=KDF.HKDF_SHA256,
        ...     aead=AEAD.AES_128_GCM,
        ...     recipient_private_key=sk_bytes,
        ...     kem_output=enc,
        ...     info=b"context",
        ...     aad=b"",
        ...     ciphertext=ciphertext
        ... )
    """
    _ensure_hpke_available()
    _kem, _kdf, _aead = _map_hpke_enums(kem, kdf, aead)
    hpke = _HPKE(_kem, _kdf, _aead, mode=_HPKE_Mode.BASE)
    plaintext = hpke.open(
        recipient_private_key=recipient_private_key,
        kem_output=kem_output,
        info=info,
        aad=aad,
        ciphertext=ciphertext,
    )
    return plaintext



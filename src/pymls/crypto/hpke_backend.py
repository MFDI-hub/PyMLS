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


def _unsupported() -> None:
    raise ConfigurationError(
        "HPKE via 'cryptography' is not available in this environment. "
        "Upgrade 'cryptography' to a version that provides HPKE support, or "
        "install a vetted HPKE backend and configure PyMLS accordingly."
    )


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
    This implementation delegates to cryptography's HPKE if available.
    """
    # Placeholder detection: cryptography currently does not expose a stable HPKE API.
    # If/when it does, import and route here. For now, fail fast.
    _unsupported()
    # The following is unreachable until HPKE is supported natively:
    # return b"", b""


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
    This implementation delegates to cryptography's HPKE if available.
    """
    _unsupported()
    # The following is unreachable until HPKE is supported natively:
    # return b""



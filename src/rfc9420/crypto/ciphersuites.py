"""MLS ciphersuite registry and helpers (RFC 9420 §16.3).

This module provides the ciphersuite registry for MLS, including definitions
for all RFC 9420 §16.3 ciphersuites. It includes enums for KEM, KDF, AEAD,
and signature schemes, as well as lookup functions for ciphersuites by ID
or name.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Iterable, List, Optional, Tuple


class KEM(IntEnum):
    """Key Encapsulation Mechanisms used by MLS ciphersuites (RFC 9420 §16.3).

    Enumeration of KEM algorithms supported by MLS ciphersuites.
    """
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021


class KDF(IntEnum):
    """Key Derivation Functions used by MLS ciphersuites (RFC 9420 §16.3).

    Enumeration of KDF algorithms (all use HKDF with various hash functions).
    """
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class AEAD(IntEnum):
    """AEAD algorithms used by MLS ciphersuites (RFC 9420 §16.3).

    Enumeration of authenticated encryption algorithms supported by MLS.
    """
    AES_128_GCM = 0x0001
    AES_256_GCM = 0x0002
    CHACHA20_POLY1305 = 0x0003


class SignatureScheme(Enum):
    """
    Signature schemes used by MLS ciphersuites (RFC 9420 §16.3).
    Names include the curve and hash when applicable to avoid ambiguity.
    """

    ED25519 = "Ed25519"
    ED448 = "Ed448"
    ECDSA_SECP256R1_SHA256 = "ECDSA_SECP256R1_SHA256"
    ECDSA_SECP384R1_SHA384 = "ECDSA_SECP384R1_SHA384"
    ECDSA_SECP521R1_SHA512 = "ECDSA_SECP521R1_SHA512"


@dataclass(frozen=True)
class MlsCiphersuite:
    """MLS ciphersuite definition combining KEM, KDF, AEAD, and signature scheme.

    A ciphersuite defines the complete set of cryptographic algorithms used
    by an MLS group. See RFC 9420 §16.3 for the complete specification.

    Attributes:
        suite_id: RFC 9420 ciphersuite identifier (e.g., 0x0001).
        name: Canonical name of the ciphersuite.
        kem: Key Encapsulation Mechanism.
        kdf: Key Derivation Function.
        aead: Authenticated Encryption with Associated Data algorithm.
        signature: Signature scheme.

    Example:
        >>> suite = get_ciphersuite_by_id(0x0001)
        >>> print(suite.name)
        MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    """

    suite_id: int
    name: str
    kem: KEM
    kdf: KDF
    aead: AEAD
    signature: SignatureScheme

    @property
    def triple(self) -> Tuple[KEM, KDF, AEAD]:
        """Return (KEM, KDF, AEAD) tuple for convenience comparisons.

        Returns:
            Tuple of (KEM, KDF, AEAD) components.
        """
        return (self.kem, self.kdf, self.aead)

    @property
    def is_ae1_secure(self) -> bool:
        """RFC 9420 §16.3 suites are AE1-secure by construction."""
        return self.aead in (AEAD.AES_128_GCM, AEAD.AES_256_GCM, AEAD.CHACHA20_POLY1305)


# RFC 9420 §16.3 ciphersuite registry
# Note: IDs and names follow the RFC. This list is intentionally explicit.
_REGISTRY_BY_ID: Dict[int, MlsCiphersuite] = {
    0x0001: MlsCiphersuite(
        suite_id=0x0001,
        name="MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        kem=KEM.DHKEM_X25519_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.AES_128_GCM,
        signature=SignatureScheme.ED25519,
    ),
    0x0002: MlsCiphersuite(
        suite_id=0x0002,
        name="MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        kem=KEM.DHKEM_P256_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.AES_128_GCM,
        signature=SignatureScheme.ECDSA_SECP256R1_SHA256,
    ),
    0x0003: MlsCiphersuite(
        suite_id=0x0003,
        name="MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519",
        kem=KEM.DHKEM_X25519_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ED25519,
    ),
    0x0004: MlsCiphersuite(
        suite_id=0x0004,
        name="MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
        kem=KEM.DHKEM_X448_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ED448,
    ),
    0x0005: MlsCiphersuite(
        suite_id=0x0005,
        name="MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
        kem=KEM.DHKEM_P521_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ECDSA_SECP521R1_SHA512,
    ),
    0x0006: MlsCiphersuite(
        suite_id=0x0006,
        name="MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
        kem=KEM.DHKEM_X448_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ED448,
    ),
    0x0007: MlsCiphersuite(
        suite_id=0x0007,
        name="MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
        kem=KEM.DHKEM_P384_HKDF_SHA384,
        kdf=KDF.HKDF_SHA384,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ECDSA_SECP384R1_SHA384,
    ),
}

_REGISTRY_BY_NAME: Dict[str, MlsCiphersuite] = {
    cs.name: cs for cs in _REGISTRY_BY_ID.values()
}


def get_ciphersuite_by_id(suite_id: int) -> Optional[MlsCiphersuite]:
    """Look up a ciphersuite by RFC suite id.

    Args:
        suite_id: RFC 9420 ciphersuite identifier (e.g., 0x0001).

    Returns:
        MlsCiphersuite instance if found, None otherwise.

    Example:
        >>> suite = get_ciphersuite_by_id(0x0001)
        >>> print(suite.name)
    """
    return _REGISTRY_BY_ID.get(suite_id)


def get_ciphersuite_by_name(name: str) -> Optional[MlsCiphersuite]:
    """Look up a ciphersuite by its canonical name.

    Args:
        name: Canonical ciphersuite name (e.g., "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519").

    Returns:
        MlsCiphersuite instance if found, None otherwise.
    """
    return _REGISTRY_BY_NAME.get(name)


def all_ciphersuites() -> Iterable[MlsCiphersuite]:
    """Iterable over registered ciphersuites (by id ascending).

    Returns:
        Iterable of all registered MlsCiphersuite instances, sorted by suite_id.
    """
    return _REGISTRY_BY_ID.values()


def list_ciphersuite_ids() -> List[int]:
    """List of all registered RFC suite ids (sorted).

    Returns:
        Sorted list of all registered ciphersuite IDs.
    """
    return sorted(_REGISTRY_BY_ID.keys())


def list_ciphersuite_names() -> List[str]:
    """List of all registered ciphersuite names (sorted).

    Returns:
        Sorted list of all registered ciphersuite names.
    """
    return sorted(_REGISTRY_BY_NAME.keys())


def find_by_triple(triple: Tuple[KEM, KDF, AEAD]) -> Optional[MlsCiphersuite]:
    """Find a ciphersuite matching the given (KEM, KDF, AEAD) triple.

    Args:
        triple: Tuple of (KEM, KDF, AEAD) to search for.

    Returns:
        MlsCiphersuite instance if a matching ciphersuite is found, None otherwise.

    Example:
        >>> triple = (KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
        >>> suite = find_by_triple(triple)
    """
    kem, kdf, aead = triple
    for cs in _REGISTRY_BY_ID.values():
        if (cs.kem, cs.kdf, cs.aead) == (kem, kdf, aead):
            return cs
    return None




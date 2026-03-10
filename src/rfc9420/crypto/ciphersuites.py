"""MLS ciphersuite registry and helpers (RFC 9420 §16.3).

This module provides the ciphersuite registry for MLS, including definitions
for all RFC 9420 §16.3 ciphersuites. KEM, KDF, and AEAD identifiers are
provided by rfc9180 (RFC 9180 HPKE) and re-exported here for MLS use.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Iterable, List, Optional, Tuple

# RFC 9420 §16.3 uses the same IANA values as RFC 9180 for KEM, KDF, AEAD.
# Re-export from rfc9180 as the single source of truth.
from rfc9180.constants import AEADID, KDFID, KEMID

KEM = KEMID
KDF = KDFID
AEAD = AEADID


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


class CipherSuiteId(IntEnum):
    """RFC 9420 §16.3 MLS ciphersuite identifiers (IANA registry)."""

    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002
    MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519 = 0x0003
    MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384 = 0x0007


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
    int(CipherSuiteId.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
        name="MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        kem=KEM.DHKEM_X25519_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.AES_128_GCM,
        signature=SignatureScheme.ED25519,
    ),
    int(CipherSuiteId.MLS_128_DHKEMP256_AES128GCM_SHA256_P256): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_128_DHKEMP256_AES128GCM_SHA256_P256),
        name="MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
        kem=KEM.DHKEM_P256_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.AES_128_GCM,
        signature=SignatureScheme.ECDSA_SECP256R1_SHA256,
    ),
    int(CipherSuiteId.MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519),
        name="MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519",
        kem=KEM.DHKEM_X25519_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ED25519,
    ),
    int(CipherSuiteId.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448),
        name="MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
        kem=KEM.DHKEM_X448_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ED448,
    ),
    int(CipherSuiteId.MLS_256_DHKEMP521_AES256GCM_SHA512_P521): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_256_DHKEMP521_AES256GCM_SHA512_P521),
        name="MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
        kem=KEM.DHKEM_P521_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ECDSA_SECP521R1_SHA512,
    ),
    int(CipherSuiteId.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
        name="MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448",
        kem=KEM.DHKEM_X448_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ED448,
    ),
    int(CipherSuiteId.MLS_256_DHKEMP384_AES256GCM_SHA384_P384): MlsCiphersuite(
        suite_id=int(CipherSuiteId.MLS_256_DHKEMP384_AES256GCM_SHA384_P384),
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




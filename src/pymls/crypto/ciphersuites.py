"""MLS ciphersuite registry and helpers (RFC 9420 §16.3)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Dict, Iterable, List, Optional, Tuple


class KEM(IntEnum):
    """Key Encapsulation Mechanisms used by MLS ciphersuites (RFC 9420 §16.3)."""
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021


class KDF(IntEnum):
    """Key Derivation Functions used by MLS ciphersuites (RFC 9420 §16.3)."""
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class AEAD(IntEnum):
    """AEAD algorithms used by MLS ciphersuites (RFC 9420 §16.3)."""
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
    ECDSA_SECP521R1_SHA512 = "ECDSA_SECP521R1_SHA512"


@dataclass(frozen=True)
class MlsCiphersuite:
    """
    MLS ciphersuite definition combining KEM, KDF, AEAD, and signature scheme.
    See RFC 9420 §16.3.
    """

    suite_id: int
    name: str
    kem: KEM
    kdf: KDF
    aead: AEAD
    signature: SignatureScheme

    @property
    def triple(self) -> Tuple[KEM, KDF, AEAD]:
        """Return (KEM, KDF, AEAD) tuple for convenience comparisons."""
        return (self.kem, self.kdf, self.aead)


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
        name="MLS_128_DHKEMP256_CHACHAPOLY_SHA256_P256",
        kem=KEM.DHKEM_P256_HKDF_SHA256,
        kdf=KDF.HKDF_SHA256,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ECDSA_SECP256R1_SHA256,
    ),
    0x0005: MlsCiphersuite(
        suite_id=0x0005,
        name="MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448",
        kem=KEM.DHKEM_X448_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ED448,
    ),
    0x0006: MlsCiphersuite(
        suite_id=0x0006,
        name="MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
        kem=KEM.DHKEM_P521_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.AES_256_GCM,
        signature=SignatureScheme.ECDSA_SECP521R1_SHA512,
    ),
    0x0007: MlsCiphersuite(
        suite_id=0x0007,
        name="MLS_256_DHKEMX448_CHACHAPOLY_SHA512_Ed448",
        kem=KEM.DHKEM_X448_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ED448,
    ),
    0x0008: MlsCiphersuite(
        suite_id=0x0008,
        name="MLS_256_DHKEMP521_CHACHAPOLY_SHA512_P521",
        kem=KEM.DHKEM_P521_HKDF_SHA512,
        kdf=KDF.HKDF_SHA512,
        aead=AEAD.CHACHA20_POLY1305,
        signature=SignatureScheme.ECDSA_SECP521R1_SHA512,
    ),
}

_REGISTRY_BY_NAME: Dict[str, MlsCiphersuite] = {
    cs.name: cs for cs in _REGISTRY_BY_ID.values()
}


def get_ciphersuite_by_id(suite_id: int) -> Optional[MlsCiphersuite]:
    """Look up a ciphersuite by RFC suite id."""
    return _REGISTRY_BY_ID.get(suite_id)


def get_ciphersuite_by_name(name: str) -> Optional[MlsCiphersuite]:
    """Look up a ciphersuite by its canonical name."""
    return _REGISTRY_BY_NAME.get(name)


def all_ciphersuites() -> Iterable[MlsCiphersuite]:
    """Iterable over registered ciphersuites (by id ascending)."""
    return _REGISTRY_BY_ID.values()


def list_ciphersuite_ids() -> List[int]:
    """List of all registered RFC suite ids (sorted)."""
    return sorted(_REGISTRY_BY_ID.keys())


def list_ciphersuite_names() -> List[str]:
    """List of all registered ciphersuite names (sorted)."""
    return sorted(_REGISTRY_BY_NAME.keys())


def find_by_triple(triple: Tuple[KEM, KDF, AEAD]) -> Optional[MlsCiphersuite]:
    """Find a ciphersuite matching the given (KEM, KDF, AEAD) triple."""
    kem, kdf, aead = triple
    for cs in _REGISTRY_BY_ID.values():
        if (cs.kem, cs.kdf, cs.aead) == (kem, kdf, aead):
            return cs
    return None




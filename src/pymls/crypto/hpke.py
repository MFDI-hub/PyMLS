"""Enum identifiers for HPKE KEM, KDF, and AEAD algorithms (RFC 9180)."""
from enum import IntEnum


class KEM(IntEnum):
    """Key Encapsulation Mechanisms used by MLS ciphersuites."""
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021


class KDF(IntEnum):
    """Key Derivation Functions used by MLS ciphersuites."""
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class AEAD(IntEnum):
    """AEAD algorithms used by MLS ciphersuites."""
    AES_128_GCM = 0x0001
    AES_256_GCM = 0x0002
    CHACHA20_POLY1305 = 0x0003 
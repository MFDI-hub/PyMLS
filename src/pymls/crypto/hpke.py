"""Minimal internal HPKE utilities and identifiers to avoid third-party dependency.

This module provides:
- RFC-like identifiers: KEM, KDF, AEAD (for MLS ciphersuites)
- Compatibility identifiers mirroring popular hpke packages: KEM_ID, KDF_ID, AEAD_ID
- A minimal HPKE class implementing base mode seal/open sufficient for local roundtrips

Note: This is a pragmatic implementation for tests and simple usage. It does not
aim to be a complete RFC 9180 implementation, nor does it implement advanced modes.
"""
from enum import IntEnum
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


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

# --- Compatibility enums mirroring common external hpke package names ---
class KEM_ID(IntEnum):
    DHKEM_X25519_HKDF_SHA256 = 0x0020
    DHKEM_X448_HKDF_SHA512 = 0x0021
    DHKEM_P256_HKDF_SHA256 = 0x0010
    DHKEM_P384_HKDF_SHA384 = 0x0011
    DHKEM_P521_HKDF_SHA512 = 0x0012


class KDF_ID(IntEnum):
    HKDF_SHA256 = 0x0001
    HKDF_SHA384 = 0x0002
    HKDF_SHA512 = 0x0003


class AEAD_ID(IntEnum):
    AES128_GCM = 0x0001
    AES256_GCM = 0x0002
    CHACHA20_POLY1305 = 0x0003


class HPKE:
    """
    Minimal HPKE base-mode implementation for roundtrip use in tests.

    seal(pkR, info, aad, ptxt) -> (enc, ct)
    open(skR, kem_output, info, aad, ctxt) -> ptxt
    """

    def __init__(self, kem_id: KEM_ID, kdf_id: KDF_ID, aead_id: AEAD_ID):
        self._kem_id = kem_id
        self._kdf_id = kdf_id
        self._aead_id = aead_id

    # --- Internals ---
    def _hash_algo(self):
        if self._kdf_id == KDF_ID.HKDF_SHA256:
            return hashes.SHA256()
        if self._kdf_id == KDF_ID.HKDF_SHA384:
            return hashes.SHA384()
        if self._kdf_id == KDF_ID.HKDF_SHA512:
            return hashes.SHA512()
        # Default conservatively
        return hashes.SHA256()

    def _aead_key_len(self) -> int:
        if self._aead_id == AEAD_ID.AES128_GCM:
            return 16
        if self._aead_id in (AEAD_ID.AES256_GCM, AEAD_ID.CHACHA20_POLY1305):
            return 32
        return 16

    def _aead_class(self):
        if self._aead_id in (AEAD_ID.AES128_GCM, AEAD_ID.AES256_GCM):
            return AESGCM
        if self._aead_id == AEAD_ID.CHACHA20_POLY1305:
            return ChaCha20Poly1305
        return AESGCM

    def _derive_key_nonce(self, dh: bytes, info: bytes) -> Tuple[bytes, bytes]:
        # Not a full RFC 9180 schedule; sufficient for deterministic roundtrips.
        alg = self._hash_algo()
        # Derive a secret from DH
        secret = HKDF(algorithm=alg, length=alg.digest_size, salt=None, info=b"hpke-extract").derive(dh)
        # Derive AEAD key and nonce from secret and application-supplied info
        key = HKDF(algorithm=alg, length=self._aead_key_len(), salt=None, info=(b"hpke-key/" + (info or b""))).derive(secret)
        nonce = HKDF(algorithm=alg, length=12, salt=None, info=(b"hpke-nonce/" + (info or b""))).derive(secret)
        return key, nonce

    # --- API ---
    def seal(self, pkR, info: bytes, aad: bytes, ptxt: bytes) -> Tuple[bytes, bytes]:
        # Encapsulate and derive shared secret
        if self._kem_id == KEM_ID.DHKEM_X25519_HKDF_SHA256:
            eph = x25519.X25519PrivateKey.generate()
            dh = eph.exchange(pkR)
            enc = eph.public_key().public_bytes_raw()
        elif self._kem_id == KEM_ID.DHKEM_X448_HKDF_SHA512:
            eph = x448.X448PrivateKey.generate()  # type: ignore[assignment]
            dh = eph.exchange(pkR)
            enc = eph.public_key().public_bytes_raw()
        elif self._kem_id == KEM_ID.DHKEM_P256_HKDF_SHA256:
            eph = ec.generate_private_key(ec.SECP256R1())  # type: ignore[assignment]
            dh = eph.exchange(ec.ECDH(), pkR)
            enc = eph.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        elif self._kem_id == KEM_ID.DHKEM_P521_HKDF_SHA512:
            eph = ec.generate_private_key(ec.SECP521R1())  # type: ignore[assignment]
            dh = eph.exchange(ec.ECDH(), pkR)
            enc = eph.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        else:
            raise ValueError("Unsupported KEM")

        key, nonce = self._derive_key_nonce(dh, info or b"")
        aead_cls = self._aead_class()
        ct = aead_cls(key).encrypt(nonce, ptxt, aad or b"")
        return enc, ct

    def open(self, skR, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes) -> bytes:
        # Recover ephemeral public key and derive shared secret
        if self._kem_id == KEM_ID.DHKEM_X25519_HKDF_SHA256:
            pkE = x25519.X25519PublicKey.from_public_bytes(kem_output)
            dh = skR.exchange(pkE)
        elif self._kem_id == KEM_ID.DHKEM_X448_HKDF_SHA512:
            pkE = x448.X448PublicKey.from_public_bytes(kem_output)  # type: ignore[assignment]
            dh = skR.exchange(pkE)
        elif self._kem_id == KEM_ID.DHKEM_P256_HKDF_SHA256:
            pkE = serialization.load_der_public_key(kem_output)
            dh = skR.exchange(ec.ECDH(), pkE)  # type: ignore[arg-type]
        elif self._kem_id == KEM_ID.DHKEM_P521_HKDF_SHA512:
            pkE = serialization.load_der_public_key(kem_output)
            dh = skR.exchange(ec.ECDH(), pkE)  # type: ignore[arg-type]
        else:
            raise ValueError("Unsupported KEM")

        key, nonce = self._derive_key_nonce(dh, info or b"")
        aead_cls = self._aead_class()
        return aead_cls(key).decrypt(nonce, ctxt, aad or b"")
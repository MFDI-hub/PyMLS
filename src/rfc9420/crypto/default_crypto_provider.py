"""Concrete CryptoProvider using the 'cryptography' and 'rfc9180-py' packages.

This module provides DefaultCryptoProvider, which implements the CryptoProvider
interface using the cryptography library for hashing, AEAD, signatures, and
rfc9180-py (imported as ``rfc9180``) for HPKE. All RFC 9420 §16.3 AE1-secure
ciphersuites are supported.
"""
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.asymmetric import (
    ec,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature

# HPKE via rfc9180-py (imported as "rfc9180")
from rfc9180 import HPKE
from rfc9180.constants import KEM_PARAMS
from .hpke_backend import (
    hpke_seal as _hpke_seal_backend, 
    hpke_open as _hpke_open_backend,
    map_hpke_enums
)

from .crypto_provider import CryptoProvider
from .ciphersuites import KDF as KDFEnum, AEAD
from ..codec.tls import write_uint16 as _write_uint16
from .ciphersuites import (
    MlsCiphersuite,
    SignatureScheme,
    get_ciphersuite_by_id,
)
from ..mls.exceptions import (
    UnsupportedCipherSuiteError,
    InvalidSignatureError,
    RFC9420Error,
)


class DefaultCryptoProvider(CryptoProvider):
    """Concrete CryptoProvider implementation using cryptography and rfc9180-py.

    Supports all RFC 9420 §16.3 AE1-secure ciphersuites. Requires the
    cryptography and rfc9180-py packages.

    Parameters:
        suite_id: MLS ciphersuite ID (default 0x0001). Must be AE1-secure.

    Raises:
        UnsupportedCipherSuiteError: If suite_id is unknown or not AE1-secure.
    """

    def __init__(self, suite_id: int = 0x0001):
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise UnsupportedCipherSuiteError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        if not cs.is_ae1_secure:
            raise UnsupportedCipherSuiteError(f"Ciphersuite is not AE1-secure: {cs.name}")
        self._suite: MlsCiphersuite = cs

    @property
    def supported_ciphersuites(self):
        return [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007]

    @property
    def active_ciphersuite(self) -> MlsCiphersuite:
        return self._suite

    def set_ciphersuite(self, suite_id: int) -> None:
        """Switch the active ciphersuite by RFC suite id.

        Raises:
            UnsupportedCipherSuiteError: If suite_id is unknown or not AE1-secure.
        """
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise UnsupportedCipherSuiteError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        if not cs.is_ae1_secure:
            raise UnsupportedCipherSuiteError(f"Ciphersuite is not AE1-secure: {cs.name}")
        self._suite = cs

    # --- Internals for algorithm selection ---
    def _hash_algo(self):
        if self._suite.kdf == KDFEnum.HKDF_SHA256:
            return hashes.SHA256()
        if self._suite.kdf == KDFEnum.HKDF_SHA512:
            return hashes.SHA512()
        return hashes.SHA384()

    def _aead_impl(self):
        if self._suite.aead == AEAD.AES_128_GCM or self._suite.aead == AEAD.AES_256_GCM:
            return AESGCM
        if self._suite.aead == AEAD.CHACHA20_POLY1305:
            return ChaCha20Poly1305
        raise UnsupportedCipherSuiteError("Unsupported AEAD")

    def _load_ec_private(self, data: bytes, curve: ec.EllipticCurve):
        """Load an EC private key from DER or PEM bytes (used for Signing)."""
        try:
            return serialization.load_der_private_key(data, password=None)
        except Exception:
            try:
                return serialization.load_pem_private_key(data, password=None)
            except Exception as e:
                raise RFC9420Error("Invalid EC private key encoding (expect DER/PEM)") from e

    def _load_ec_public(self, data: bytes, curve: ec.EllipticCurve):
        """Load an EC public key from RFC8446 point format, DER, or PEM."""
        if data and data[0] == 0x04:
            try:
                return ec.EllipticCurvePublicKey.from_encoded_point(curve, data)
            except Exception:
                pass
        try:
            return serialization.load_der_public_key(data)
        except Exception:
            try:
                return serialization.load_pem_public_key(data)
            except Exception as e:
                raise RFC9420Error("Invalid EC public key encoding (expect DER/PEM)") from e

    def _get_hpke_instance(self) -> HPKE:
        """Helper to create an rfc9180-py HPKE instance for the active suite."""
        kem_id, kdf_id, aead_id = map_hpke_enums(
            self._suite.kem, self._suite.kdf, self._suite.aead
        )
        return HPKE(kem_id, kdf_id, aead_id)

    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm) per RFC 5869 §2.2.

        If salt is empty, uses a zero-filled key of Hash.length bytes.
        Output length equals the hash digest size (Hash.length).
        """
        effective_salt = salt if salt else bytes(self._hash_algo().digest_size)
        h = hmac.HMAC(effective_salt, self._hash_algo())
        h.update(ikm)
        return h.finalize()

    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand(prk, info, length) per RFC 5869 §2.3."""
        return HKDFExpand(
            algorithm=self._hash_algo(),
            length=length,
            info=info,
        ).derive(prk)

    def hash(self, data: bytes) -> bytes:
        h = hashes.Hash(self._hash_algo())
        h.update(data)
        return h.finalize()

    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        aead = self._aead_impl()
        return aead(key).encrypt(nonce, plaintext, aad)

    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        aead = self._aead_impl()
        return aead(key).decrypt(nonce, ciphertext, aad)

    def hmac_sign(self, key: bytes, data: bytes) -> bytes:
        h = hmac.HMAC(key, self._hash_algo())
        h.update(data)
        return h.finalize()

    def hmac_verify(self, key: bytes, data: bytes, tag: bytes) -> None:
        h = hmac.HMAC(key, self._hash_algo())
        h.update(data)
        h.verify(tag)

    def sign(self, private_key: bytes, data: bytes) -> bytes:
        scheme = self._suite.signature
        if scheme == SignatureScheme.ED25519:
            sk = Ed25519PrivateKey.from_private_bytes(private_key)
            return sk.sign(data)
        if scheme == SignatureScheme.ED448:
            sk_448 = Ed448PrivateKey.from_private_bytes(private_key) # FIX 2 (mypy assignment error)
            return sk_448.sign(data)
        if scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
            sk = self._load_ec_private(private_key, ec.SECP256R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA256()))
        if scheme == SignatureScheme.ECDSA_SECP384R1_SHA384:
            sk = self._load_ec_private(private_key, ec.SECP384R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA384()))
        if scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
            sk = self._load_ec_private(private_key, ec.SECP521R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA512()))
        raise UnsupportedCipherSuiteError("Unsupported signature scheme")

    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None:
        scheme = self._suite.signature
        try:
            if scheme == SignatureScheme.ED25519:
                pk = Ed25519PublicKey.from_public_bytes(public_key)
                pk.verify(signature, data)
                return
            if scheme == SignatureScheme.ED448:
                pk_448 = Ed448PublicKey.from_public_bytes(public_key) # FIX 3 (mypy assignment error)
                pk_448.verify(signature, data)
                return
            if scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
                pk = self._load_ec_public(public_key, ec.SECP256R1())
                pk.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return
            if scheme == SignatureScheme.ECDSA_SECP384R1_SHA384:
                pk = self._load_ec_public(public_key, ec.SECP384R1())
                pk.verify(signature, data, ec.ECDSA(hashes.SHA384()))
                return
            if scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
                pk = self._load_ec_public(public_key, ec.SECP521R1())
                pk.verify(signature, data, ec.ECDSA(hashes.SHA512()))
                return
        except InvalidSignature as e:
            raise InvalidSignatureError("invalid signature") from e
        raise UnsupportedCipherSuiteError("Unsupported signature scheme")

    # --- Domain-separated signing ---
    @staticmethod
    def _encode_sign_content(label: bytes, content: bytes) -> bytes:
        """Encode SignContent per RFC 9420 §5.1.2.

        struct { opaque label<V>; opaque content<V>; } SignContent;
        Uses varint (write_opaque_varint) length prefixes per RFC 9420 §2.1.2.
        """
        from ..codec.tls import write_opaque_varint
        return write_opaque_varint(label or b"") + write_opaque_varint(content or b"")

    def sign_with_label(self, private_key: bytes, label: bytes, content: bytes) -> bytes:
        full = b"MLS 1.0 " + (label or b"")
        data = self._encode_sign_content(full, content)
        return self.sign(private_key, data)

    def verify_with_label(self, public_key: bytes, label: bytes, content: bytes, signature: bytes) -> None:
        full = b"MLS 1.0 " + (label or b"")
        data = self._encode_sign_content(full, content)
        self.verify(public_key, data, signature)

    def signature_public_from_private(self, private_key: bytes) -> bytes:
        """Derive the public signing key bytes from a private signing key."""
        scheme = self._suite.signature
        if scheme == SignatureScheme.ED25519:
            sk = Ed25519PrivateKey.from_private_bytes(private_key)
            return sk.public_key().public_bytes_raw()
        if scheme == SignatureScheme.ED448:
            sk_448 = Ed448PrivateKey.from_private_bytes(private_key)
            return sk_448.public_key().public_bytes_raw()
        if scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
            sk = self._load_ec_private(private_key, ec.SECP256R1())
            return sk.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        if scheme == SignatureScheme.ECDSA_SECP384R1_SHA384:
            sk = self._load_ec_private(private_key, ec.SECP384R1())
            return sk.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        if scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
            sk = self._load_ec_private(private_key, ec.SECP521R1())
            return sk.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        raise UnsupportedCipherSuiteError("Unsupported signature scheme")

    def hpke_seal(self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes) -> tuple[bytes, bytes]:
        return _hpke_seal_backend(
            kem=self._suite.kem,
            kdf=self._suite.kdf,
            aead=self._suite.aead,
            recipient_public_key=public_key,
            info=info,
            aad=aad,
            plaintext=ptxt,
        )

    def hpke_open(self, private_key: bytes, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes) -> bytes:
        return _hpke_open_backend(
            kem=self._suite.kem,
            kdf=self._suite.kdf,
            aead=self._suite.aead,
            recipient_private_key=private_key,
            kem_output=kem_output,
            info=info,
            aad=aad,
            ciphertext=ctxt,
        )

    def hpke_export_secret(self, private_key: bytes, kem_output: bytes, info: bytes, export_label: bytes, export_length: int) -> bytes:
        from .hpke_backend import hpke_export_secret as _hpke_export_backend
        return _hpke_export_backend(
            kem=self._suite.kem,
            kdf=self._suite.kdf,
            aead=self._suite.aead,
            recipient_private_key=private_key,
            kem_output=kem_output,
            info=info,
            export_label=export_label,
            export_length=export_length,
        )

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate a KEM key pair using rfc9180-py."""
        hpke = self._get_hpke_instance()
        sk, pk = hpke.generate_key_pair()
        return hpke.serialize_private_key(sk), hpke.serialize_public_key(pk)

    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        """Derive a deterministic KEM key pair using rfc9180-py."""
        hpke = self._get_hpke_instance()
        sk, pk = hpke.derive_key_pair(seed)
        return hpke.serialize_private_key(sk), hpke.serialize_public_key(pk)

    def kem_pk_size(self) -> int:
        """Return the public key size for the active KEM using rfc9180-py params."""
        kem_id, _, _ = map_hpke_enums(self._suite.kem, self._suite.kdf, self._suite.aead)
        params = KEM_PARAMS.get(kem_id)
        if params and 'Npk' in params:
            return params['Npk']
        raise UnsupportedCipherSuiteError("Unknown KEM parameters")

    def aead_key_size(self) -> int:
        if self._suite.aead == AEAD.AES_128_GCM:
            return 16
        if self._suite.aead in (AEAD.AES_256_GCM, AEAD.CHACHA20_POLY1305):
            return 32
        raise UnsupportedCipherSuiteError("Unsupported AEAD")

    def aead_nonce_size(self) -> int:
        return 12

    def kdf_hash_len(self) -> int:
        return self._hash_algo().digest_size

    def expand_with_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        full_label = b"MLS 1.0 " + (label or b"")
        from ..codec.tls import write_opaque_varint
        info = _write_uint16(length) + write_opaque_varint(full_label) + write_opaque_varint(context or b"")
        return self.kdf_expand(secret, info, length)

    def derive_secret(self, secret: bytes, label: bytes) -> bytes:
        return self.expand_with_label(secret, label, b"", self.kdf_hash_len())
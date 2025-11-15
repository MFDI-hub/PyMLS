"""Concrete CryptoProvider using the 'cryptography' and 'hpke' Python packages."""
import struct
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import (
    x25519,
    x448,
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

from .hpke_backend import hpke_seal as _hpke_seal_backend, hpke_open as _hpke_open_backend

from .crypto_provider import CryptoProvider
from .ciphersuites import KEM, KDF as KDFEnum, AEAD
from ..codec.tls import write_uint16 as _write_uint16
from ..codec.tls import write_opaque8 as _write_opaque8, write_opaque16 as _write_opaque16
from .ciphersuites import (
    MlsCiphersuite,
    SignatureScheme,
    get_ciphersuite_by_id,
)
from ..mls.exceptions import (
    UnsupportedCipherSuiteError,
    InvalidSignatureError,
    PyMLSError,
)


class DefaultCryptoProvider(CryptoProvider):
    def __init__(self, suite_id: int = 0x0001):
        """Initialize with the given MLS ciphersuite id."""
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise UnsupportedCipherSuiteError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        self._suite: MlsCiphersuite = cs

    @property
    def supported_ciphersuites(self):
        """RFC suite ids supported by this provider."""
        # Return RFC suite ids
        return [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008]

    @property
    def active_ciphersuite(self) -> MlsCiphersuite:
        """Active ciphersuite object."""
        return self._suite

    def set_ciphersuite(self, suite_id: int) -> None:
        """Select a different active ciphersuite by id."""
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise UnsupportedCipherSuiteError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        self._suite = cs

    # --- Internals for algorithm selection ---
    def _hash_algo(self):
        """Return a cryptography HashAlgorithm for the active KDF."""
        if self._suite.kdf == KDFEnum.HKDF_SHA256:
            return hashes.SHA256()
        if self._suite.kdf == KDFEnum.HKDF_SHA512:
            return hashes.SHA512()
        # HKDF_SHA384 not used by RFC-defined suites but keep for completeness
        return hashes.SHA384()

    def _aead_impl(self):
        """Return the AEAD class for the active suite."""
        if self._suite.aead == AEAD.AES_128_GCM or self._suite.aead == AEAD.AES_256_GCM:
            return AESGCM
        if self._suite.aead == AEAD.CHACHA20_POLY1305:
            return ChaCha20Poly1305
        raise UnsupportedCipherSuiteError("Unsupported AEAD")

    def _load_ec_private(self, data: bytes, curve: ec.EllipticCurve):
        """Load an EC private key from DER or PEM bytes."""
        try:
            return serialization.load_der_private_key(data, password=None)
        except Exception:
            try:
                return serialization.load_pem_private_key(data, password=None)
            except Exception as e:
                raise PyMLSError("Invalid EC private key encoding (expect DER/PEM)") from e

    def _load_ec_public(self, data: bytes, curve: ec.EllipticCurve):
        """Load an EC public key from DER or PEM bytes."""
        try:
            return serialization.load_der_public_key(data)
        except Exception:
            try:
                return serialization.load_pem_public_key(data)
            except Exception as e:
                raise PyMLSError("Invalid EC public key encoding (expect DER/PEM)") from e

    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract using the active hash algorithm."""
        hkdf = HKDF(
            algorithm=self._hash_algo(),
            length=32,
            salt=salt,
            info=None,
        )
        return hkdf.derive(ikm)

    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand using the active hash algorithm."""
        hkdf = HKDF(
            algorithm=self._hash_algo(),
            length=length,
            salt=None,
            info=info,
        )
        return hkdf.derive(prk)

    def hash(self, data: bytes) -> bytes:
        """Compute Hash(data) using the active ciphersuite's hash algorithm."""
        h = hashes.Hash(self._hash_algo())
        h.update(data)
        return h.finalize()

    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Encrypt using the active AEAD implementation."""
        aead = self._aead_impl()
        return aead(key).encrypt(nonce, plaintext, aad)

    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt using the active AEAD implementation."""
        aead = self._aead_impl()
        return aead(key).decrypt(nonce, ciphertext, aad)

    def hmac_sign(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC over data."""
        h = hmac.HMAC(key, self._hash_algo())
        h.update(data)
        return h.finalize()

    def hmac_verify(self, key: bytes, data: bytes, tag: bytes) -> None:
        """Verify HMAC tag, raising on mismatch."""
        h = hmac.HMAC(key, self._hash_algo())
        h.update(data)
        h.verify(tag)

    def sign(self, private_key: bytes, data: bytes) -> bytes:
        """Sign data according to the active signature scheme."""
        scheme = self._suite.signature
        if scheme == SignatureScheme.ED25519:
            sk = Ed25519PrivateKey.from_private_bytes(private_key)
            return sk.sign(data)
        if scheme == SignatureScheme.ED448:
            sk = Ed448PrivateKey.from_private_bytes(private_key)  # type: ignore[assignment]
            return sk.sign(data)
        if scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
            sk = self._load_ec_private(private_key, ec.SECP256R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA256()))
        if scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
            sk = self._load_ec_private(private_key, ec.SECP521R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA512()))
        raise UnsupportedCipherSuiteError("Unsupported signature scheme")

    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None:
        """Verify signature according to the active signature scheme."""
        scheme = self._suite.signature
        try:
            if scheme == SignatureScheme.ED25519:
                pk = Ed25519PublicKey.from_public_bytes(public_key)
                pk.verify(signature, data)
                return
            if scheme == SignatureScheme.ED448:
                pk = Ed448PublicKey.from_public_bytes(public_key)  # type: ignore[assignment]
                pk.verify(signature, data)
                return
            if scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
                pk = self._load_ec_public(public_key, ec.SECP256R1())
                pk.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return
            if scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
                pk = self._load_ec_public(public_key, ec.SECP521R1())
                pk.verify(signature, data, ec.ECDSA(hashes.SHA512()))
                return
        except InvalidSignature as e:
            raise InvalidSignatureError("invalid signature") from e
        raise UnsupportedCipherSuiteError("Unsupported signature scheme")

    # --- Domain-separated signing (RFC 9420 §5.1.2) ---
    @staticmethod
    def _encode_sign_content(label: bytes, content: bytes) -> bytes:
        """
        Serialize SignContent := uint32(len(label)) || label || uint32(len(content)) || content
        Matching protocol.data_structures.SignContent.serialize().
        """
        return struct.pack("!L", len(label)) + (label or b"") + struct.pack("!L", len(content)) + (content or b"")

    def sign_with_label(self, private_key: bytes, label: bytes, content: bytes) -> bytes:
        """Sign serialized SignContent(label, content)."""
        data = self._encode_sign_content(label, content)
        return self.sign(private_key, data)

    def verify_with_label(self, public_key: bytes, label: bytes, content: bytes, signature: bytes) -> None:
        """Verify signature over serialized SignContent(label, content)."""
        full = b"MLS 1.0 " + (label or b"")
        data = self._encode_sign_content(full, content)
        self.verify(public_key, data, signature)

    def hpke_seal(self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes) -> tuple[bytes, bytes]:
        """HPKE seal using the active suite (cryptography backend)."""
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
        """HPKE open using the active suite (cryptography backend)."""
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

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate a KEM key pair compatible with the active suite."""
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        if self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            sk = x448.X448PrivateKey.generate()  # type: ignore[assignment]
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        if self._suite.kem == KEM.DHKEM_P256_HKDF_SHA256:
            sk = ec.generate_private_key(ec.SECP256R1())  # type: ignore[assignment]
            pk = sk.public_key()
            return (
                sk.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                pk.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
        if self._suite.kem == KEM.DHKEM_P521_HKDF_SHA512:
            sk = ec.generate_private_key(ec.SECP521R1())  # type: ignore[assignment]
            pk = sk.public_key()
            return (
                sk.private_bytes(
                    serialization.Encoding.DER,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                pk.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            )
        raise UnsupportedCipherSuiteError("Unsupported KEM")

    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        """Derive a deterministic KEM key pair when supported by the active suite."""
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            sk = x25519.X25519PrivateKey.from_private_bytes(seed)
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        if self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            sk = x448.X448PrivateKey.from_private_bytes(seed)  # type: ignore[assignment]
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        # For EC (P-256/521), deriving a private key from an arbitrary seed requires
        # KEM-specific DeriveKeyPair. Defer to higher-level logic for these suites.
        raise NotImplementedError("derive_key_pair not implemented for EC KEMs")

    def kem_pk_size(self) -> int:
        """Return the raw public key size for KEMs with fixed-length encodings."""
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            return 32
        if self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            return 56
        if self._suite.kem == KEM.DHKEM_P256_HKDF_SHA256:
            # Size of DER-encoded SubjectPublicKeyInfo varies. Not used for parsing split.
            # Callers should not rely on this for EC suites.
            raise NotImplementedError("kem_pk_size not defined for EC KEMs with DER encoding")
        if self._suite.kem == KEM.DHKEM_P521_HKDF_SHA512:
            raise NotImplementedError("kem_pk_size not defined for EC KEMs with DER encoding")
        raise UnsupportedCipherSuiteError("Unsupported KEM")

    def aead_key_size(self) -> int:
        if self._suite.aead == AEAD.AES_128_GCM:
            return 16
        if self._suite.aead in (AEAD.AES_256_GCM, AEAD.CHACHA20_POLY1305):
            return 32
        raise UnsupportedCipherSuiteError("Unsupported AEAD")

    def aead_nonce_size(self) -> int:
        # All RFC-defined AEADs use 96-bit nonces
        return 12

    def kdf_hash_len(self) -> int:
        """Digest length for the active KDF's hash function (bytes)."""
        return self._hash_algo().digest_size

    # --- RFC 9420 labeled helpers ---
    def expand_with_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        # info := uint16(length) || opaque8("MLS 1.0 " + label) || opaque16(context)
        full_label = b"MLS 1.0 " + (label or b"")
        info = _write_uint16(length) + _write_opaque8(full_label) + _write_opaque16(context or b"")
        return self.kdf_expand(secret, info, length)

    def derive_secret(self, secret: bytes, label: bytes) -> bytes:
        """Expand with RFC label to Hash.length with empty context."""
        return self.expand_with_label(secret, label, b"", self.kdf_hash_len())

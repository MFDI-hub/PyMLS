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
from hpke import HPKE, KEM_ID, KDF_ID, AEAD_ID

from .crypto_provider import CryptoProvider
from .hpke import KEM, KDF as KDFEnum, AEAD
from ..codec.tls import write_uint16 as _write_uint16
from ..codec.tls import write_opaque8 as _write_opaque8, write_opaque16 as _write_opaque16
from .ciphersuites import (
    MlsCiphersuite,
    SignatureScheme,
    get_ciphersuite_by_id,
)


class DefaultCryptoProvider(CryptoProvider):
    def __init__(self, suite_id: int = 0x0001):
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise ValueError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        self._suite: MlsCiphersuite = cs

    @property
    def supported_ciphersuites(self):
        # Return RFC suite ids
        return [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008]

    @property
    def active_ciphersuite(self) -> MlsCiphersuite:
        return self._suite

    def set_ciphersuite(self, suite_id: int) -> None:
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise ValueError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        self._suite = cs

    # --- Internals for algorithm selection ---
    def _hash_algo(self):
        if self._suite.kdf == KDFEnum.HKDF_SHA256:
            return hashes.SHA256()
        if self._suite.kdf == KDFEnum.HKDF_SHA512:
            return hashes.SHA512()
        # HKDF_SHA384 not used by RFC-defined suites but keep for completeness
        return hashes.SHA384()

    def _aead_impl(self):
        if self._suite.aead == AEAD.AES_128_GCM or self._suite.aead == AEAD.AES_256_GCM:
            return AESGCM
        if self._suite.aead == AEAD.CHACHA20_POLY1305:
            return ChaCha20Poly1305
        raise ValueError("Unsupported AEAD")

    def _hpke_ids(self):
        kem_id = {
            KEM.DHKEM_X25519_HKDF_SHA256: KEM_ID.DHKEM_X25519_HKDF_SHA256,
            KEM.DHKEM_X448_HKDF_SHA512: KEM_ID.DHKEM_X448_HKDF_SHA512,
            KEM.DHKEM_P256_HKDF_SHA256: KEM_ID.DHKEM_P256_HKDF_SHA256,
            KEM.DHKEM_P521_HKDF_SHA512: KEM_ID.DHKEM_P521_HKDF_SHA512,
        }[self._suite.kem]

        kdf_id = {
            KDFEnum.HKDF_SHA256: KDF_ID.HKDF_SHA256,
            KDFEnum.HKDF_SHA512: KDF_ID.HKDF_SHA512,
            KDFEnum.HKDF_SHA384: KDF_ID.HKDF_SHA384,
        }[self._suite.kdf]

        aead_id = {
            AEAD.AES_128_GCM: AEAD_ID.AES128_GCM,
            AEAD.AES_256_GCM: AEAD_ID.AES256_GCM,
            AEAD.CHACHA20_POLY1305: AEAD_ID.CHACHA20_POLY1305,
        }[self._suite.aead]
        return kem_id, kdf_id, aead_id

    def _load_ec_private(self, data: bytes, curve: ec.EllipticCurve):
        try:
            return serialization.load_der_private_key(data, password=None)
        except Exception:
            try:
                return serialization.load_pem_private_key(data, password=None)
            except Exception as e:
                raise ValueError("Invalid EC private key encoding (expect DER/PEM)") from e

    def _load_ec_public(self, data: bytes, curve: ec.EllipticCurve):
        try:
            return serialization.load_der_public_key(data)
        except Exception:
            try:
                return serialization.load_pem_public_key(data)
            except Exception as e:
                raise ValueError("Invalid EC public key encoding (expect DER/PEM)") from e

    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=self._hash_algo(),
            length=32,
            salt=salt,
            info=None,
        )
        return hkdf.derive(ikm)

    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        hkdf = HKDF(
            algorithm=self._hash_algo(),
            length=length,
            salt=None,
            info=info,
        )
        return hkdf.expand(prk)

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
            sk = Ed448PrivateKey.from_private_bytes(private_key)
            return sk.sign(data)
        if scheme == SignatureScheme.ECDSA_SECP256R1_SHA256:
            sk = self._load_ec_private(private_key, ec.SECP256R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA256()))
        if scheme == SignatureScheme.ECDSA_SECP521R1_SHA512:
            sk = self._load_ec_private(private_key, ec.SECP521R1())
            return sk.sign(data, ec.ECDSA(hashes.SHA512()))
        raise ValueError("Unsupported signature scheme")

    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None:
        scheme = self._suite.signature
        try:
            if scheme == SignatureScheme.ED25519:
                pk = Ed25519PublicKey.from_public_bytes(public_key)
                pk.verify(signature, data)
                return
            if scheme == SignatureScheme.ED448:
                pk = Ed448PublicKey.from_public_bytes(public_key)
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
            raise e
        raise ValueError("Unsupported signature scheme")

    def hpke_seal(self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes) -> tuple[bytes, bytes]:
        kem_id, kdf_id, aead_id = self._hpke_ids()
        hpke = HPKE(kem_id=kem_id, kdf_id=kdf_id, aead_id=aead_id)
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            pkR = x25519.X25519PublicKey.from_public_bytes(public_key)
        elif self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            pkR = x448.X448PublicKey.from_public_bytes(public_key)
        elif self._suite.kem == KEM.DHKEM_P256_HKDF_SHA256:
            pkR = self._load_ec_public(public_key, ec.SECP256R1())
        elif self._suite.kem == KEM.DHKEM_P521_HKDF_SHA512:
            pkR = self._load_ec_public(public_key, ec.SECP521R1())
        else:
            raise ValueError("Unsupported KEM")
        enc, ct = hpke.seal(pkR, info, aad, ptxt)
        return enc, ct

    def hpke_open(self, private_key: bytes, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes) -> bytes:
        kem_id, kdf_id, aead_id = self._hpke_ids()
        hpke = HPKE(kem_id=kem_id, kdf_id=kdf_id, aead_id=aead_id)
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            skR = x25519.X25519PrivateKey.from_private_bytes(private_key)
        elif self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            skR = x448.X448PrivateKey.from_private_bytes(private_key)
        elif self._suite.kem == KEM.DHKEM_P256_HKDF_SHA256:
            skR = self._load_ec_private(private_key, ec.SECP256R1())
        elif self._suite.kem == KEM.DHKEM_P521_HKDF_SHA512:
            skR = self._load_ec_private(private_key, ec.SECP521R1())
        else:
            raise ValueError("Unsupported KEM")
        return hpke.open(skR, kem_output, info, aad, ctxt)

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            sk = x25519.X25519PrivateKey.generate()
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        if self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            sk = x448.X448PrivateKey.generate()
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        if self._suite.kem == KEM.DHKEM_P256_HKDF_SHA256:
            sk = ec.generate_private_key(ec.SECP256R1())
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
            sk = ec.generate_private_key(ec.SECP521R1())
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
        raise ValueError("Unsupported KEM")

    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        if self._suite.kem == KEM.DHKEM_X25519_HKDF_SHA256:
            sk = x25519.X25519PrivateKey.from_private_bytes(seed)
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        if self._suite.kem == KEM.DHKEM_X448_HKDF_SHA512:
            sk = x448.X448PrivateKey.from_private_bytes(seed)
            pk = sk.public_key()
            return sk.private_bytes_raw(), pk.public_bytes_raw()
        # For EC (P-256/521), deriving a private key from an arbitrary seed requires
        # KEM-specific DeriveKeyPair. Defer to higher-level logic for these suites.
        raise NotImplementedError("derive_key_pair not implemented for EC KEMs")

    def kem_pk_size(self) -> int:
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
        raise ValueError("Unsupported KEM")

    def aead_key_size(self) -> int:
        if self._suite.aead == AEAD.AES_128_GCM:
            return 16
        if self._suite.aead in (AEAD.AES_256_GCM, AEAD.CHACHA20_POLY1305):
            return 32
        raise ValueError("Unsupported AEAD")

    def aead_nonce_size(self) -> int:
        # All RFC-defined AEADs use 96-bit nonces
        return 12

    def kdf_hash_len(self) -> int:
        return self._hash_algo().digest_size

    # --- RFC 9420 labeled helpers ---
    def expand_with_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        # info := uint16(length) || opaque8("MLS 1.0 " + label) || opaque16(context)
        full_label = b"MLS 1.0 " + (label or b"")
        info = _write_uint16(length) + _write_opaque8(full_label) + _write_opaque16(context or b"")
        return self.kdf_expand(secret, info, length)

    def derive_secret(self, secret: bytes, label: bytes) -> bytes:
        return self.expand_with_label(secret, label, b"", self.kdf_hash_len())

"""Default CryptoProvider implementation using cryptography and rfc9180 (HPKE).

Batteries-included backend; all RFC 9420 §16.3 AE1-secure ciphersuites supported.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.exceptions import InvalidSignature

from rfc9180 import HPKE
from rfc9180.constants import AEAD_PARAMS, KEM_PARAMS

from rfc9180.primitives.aead import AEADBase
from rfc9180.primitives.kdf import KDFBase

from .hpke_backend import (
    hpke_open as _hpke_open_backend,
    hpke_seal as _hpke_seal_backend,
    map_hpke_enums,
)
from ...crypto.ciphersuites import (
    CipherSuiteId,
    KEM as KEMEnum,
    KDF as KDFEnum,
    MlsCiphersuite,
    SignatureScheme,
    get_ciphersuite_by_id,
)
from ...codec.tls import write_uint16 as _write_uint16, write_opaque_varint
from ...mls.exceptions import (
    InvalidSignatureError,
    RFC9420Error,
    UnsupportedCipherSuiteError,
)


class DefaultCryptoProvider:
    """Concrete CryptoProvider implementation using cryptography and rfc9180.

    Supports all RFC 9420 §16.3 AE1-secure ciphersuites. Requires the
    cryptography and rfc9180 packages.

    Parameters
    ----------
    suite_id : int, optional
        RFC ciphersuite id (default MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
    """

    def __init__(self, suite_id: int = CipherSuiteId.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519):
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise UnsupportedCipherSuiteError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        if not cs.is_ae1_secure:
            raise UnsupportedCipherSuiteError(f"Ciphersuite is not AE1-secure: {cs.name}")
        self._suite: MlsCiphersuite = cs

    @property
    def supported_ciphersuites(self):
        return [c.value for c in CipherSuiteId]

    @property
    def active_ciphersuite(self) -> MlsCiphersuite:
        return self._suite

    def set_ciphersuite(self, suite_id: int) -> None:
        cs = get_ciphersuite_by_id(suite_id)
        if not cs:
            raise UnsupportedCipherSuiteError(f"Unsupported MLS ciphersuite id: {suite_id:#06x}")
        if not cs.is_ae1_secure:
            raise UnsupportedCipherSuiteError(f"Ciphersuite is not AE1-secure: {cs.name}")
        self._suite = cs

    def _hash_algo(self):
        if self._suite.kdf == KDFEnum.HKDF_SHA256:
            return hashes.SHA256()
        if self._suite.kdf == KDFEnum.HKDF_SHA512:
            return hashes.SHA512()
        return hashes.SHA384()

    def _aead_impl(self) -> AEADBase:
        return AEADBase(self._suite.aead)

    def _get_kdf(self) -> KDFBase:
        return KDFBase(self._suite.kdf)

    def _load_ec_private(self, data: bytes, curve: ec.EllipticCurve):
        try:
            return serialization.load_der_private_key(data, password=None)
        except Exception:
            try:
                return serialization.load_pem_private_key(data, password=None)
            except Exception as e:
                raise RFC9420Error("Invalid EC private key encoding (expect DER/PEM)") from e

    def _load_ec_public(self, data: bytes, curve: ec.EllipticCurve):
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
        kem_id, kdf_id, aead_id = map_hpke_enums(self._suite.kem, self._suite.kdf, self._suite.aead)
        return HPKE(kem_id, kdf_id, aead_id)

    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        return self._get_kdf().extract(salt, ikm)

    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        return self._get_kdf().expand(prk, info, length)

    def hash(self, data: bytes) -> bytes:
        h = hashes.Hash(self._hash_algo())
        h.update(data)
        return h.finalize()

    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return self._aead_impl().seal(key, nonce, aad, plaintext)

    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return self._aead_impl().open(key, nonce, aad, ciphertext)

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
            sk_448 = Ed448PrivateKey.from_private_bytes(private_key)
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
                pk_448 = Ed448PublicKey.from_public_bytes(public_key)
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

    @staticmethod
    def _encode_sign_content(label: bytes, content: bytes) -> bytes:
        return write_opaque_varint(label or b"") + write_opaque_varint(content or b"")

    def sign_with_label(self, private_key: bytes, label: bytes, content: bytes) -> bytes:
        full = b"MLS 1.0 " + (label or b"")
        data = self._encode_sign_content(full, content)
        return self.sign(private_key, data)

    def verify_with_label(
        self, public_key: bytes, label: bytes, content: bytes, signature: bytes
    ) -> None:
        full = b"MLS 1.0 " + (label or b"")
        data = self._encode_sign_content(full, content)
        self.verify(public_key, data, signature)

    def signature_public_from_private(self, private_key: bytes) -> bytes:
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

    def hpke_seal(
        self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes
    ) -> tuple[bytes, bytes]:
        return _hpke_seal_backend(
            kem=self._suite.kem,
            kdf=self._suite.kdf,
            aead=self._suite.aead,
            recipient_public_key=public_key,
            info=info,
            aad=aad,
            plaintext=ptxt,
        )

    def _normalize_hpke_private_key(self, private_key: bytes) -> bytes:
        if self._suite.kem not in (
            KEMEnum.DHKEM_P256_HKDF_SHA256,
            KEMEnum.DHKEM_P384_HKDF_SHA384,
            KEMEnum.DHKEM_P521_HKDF_SHA512,
        ):
            return private_key
        kem_id, _, _ = map_hpke_enums(self._suite.kem, self._suite.kdf, self._suite.aead)
        params = KEM_PARAMS.get(kem_id)
        if not params or "Nsk" not in params:
            return private_key
        nsk = int(params["Nsk"])
        if len(private_key) >= nsk:
            return private_key
        return private_key.rjust(nsk, b"\x00")

    def hpke_open(
        self, private_key: bytes, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes
    ) -> bytes:
        private_key = self._normalize_hpke_private_key(private_key)
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

    def hpke_export_secret(
        self,
        private_key: bytes,
        kem_output: bytes,
        info: bytes,
        export_label: bytes,
        export_length: int,
    ) -> bytes:
        from .hpke_backend import hpke_export_secret as _hpke_export_backend

        private_key = self._normalize_hpke_private_key(private_key)
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

    def hpke_seal_and_export(
        self,
        public_key: bytes,
        info: bytes,
        aad: bytes,
        ptxt: bytes,
        export_label: bytes,
        export_length: int,
    ) -> tuple[bytes, bytes, bytes]:
        from .hpke_backend import hpke_seal_and_export as _hpke_seal_export_backend

        return _hpke_seal_export_backend(
            kem=self._suite.kem,
            kdf=self._suite.kdf,
            aead=self._suite.aead,
            recipient_public_key=public_key,
            info=info,
            aad=aad,
            plaintext=ptxt,
            export_label=export_label,
            export_length=export_length,
        )

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        hpke = self._get_hpke_instance()
        sk, pk = hpke.generate_key_pair()
        return hpke.serialize_private_key(sk), hpke.serialize_public_key(pk)

    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        nsk = self.kem_sk_ikm_min_size()
        if len(seed) < nsk:
            seed = self.expand_with_label(seed, b"hpke ikm", b"", nsk)
        hpke = self._get_hpke_instance()
        sk, pk = hpke.derive_key_pair(seed)
        return hpke.serialize_private_key(sk), hpke.serialize_public_key(pk)

    def kem_pk_size(self) -> int:
        kem_id, _, _ = map_hpke_enums(self._suite.kem, self._suite.kdf, self._suite.aead)
        params = KEM_PARAMS.get(kem_id)
        if params and "Npk" in params:
            return params["Npk"]
        raise UnsupportedCipherSuiteError("Unknown KEM parameters")

    def kem_sk_ikm_min_size(self) -> int:
        kem_id, _, _ = map_hpke_enums(self._suite.kem, self._suite.kdf, self._suite.aead)
        params = KEM_PARAMS.get(kem_id)
        if params and "Nsk" in params:
            return params["Nsk"]
        return self.kdf_hash_len()

    def aead_key_size(self) -> int:
        params = AEAD_PARAMS.get(self._suite.aead)
        if params and "Nk" in params:
            return params["Nk"]
        raise UnsupportedCipherSuiteError("Unsupported AEAD")

    def aead_nonce_size(self) -> int:
        params = AEAD_PARAMS.get(self._suite.aead)
        if params and "Nn" in params:
            return params["Nn"]
        return 12

    def kdf_hash_len(self) -> int:
        return self._get_kdf().Nh

    def expand_with_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        full_label = b"MLS 1.0 " + (label or b"")
        info = (
            _write_uint16(length)
            + write_opaque_varint(full_label)
            + write_opaque_varint(context or b"")
        )
        return self.kdf_expand(secret, info, length)

    def derive_secret(self, secret: bytes, label: bytes) -> bytes:
        return self.expand_with_label(secret, label, b"", self.kdf_hash_len())

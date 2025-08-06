from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hmac
from cryptography.exceptions import InvalidSignature
from hpke import HPKE, KEM_ID, KDF_ID, AEAD_ID

from .crypto_provider import CryptoProvider
from .hpke import KEM, KDF as KDFEnum, AEAD


class DefaultCryptoProvider(CryptoProvider):
    def __init__(self):
        self._ciphersuites = {
            (KEM.DHKEM_X25519_HKDF_SHA256, KDFEnum.HKDF_SHA256, AEAD.AES_128_GCM): {
                "kem": x25519,
                "hash": hashes.SHA256,
                "aead": AESGCM,
            }
        }

    @property
    def supported_ciphersuites(self):
        return self._ciphersuites.keys()

    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=None,
        )
        return hkdf.derive(ikm)

    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
        )
        return hkdf.expand(prk)

    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def hmac_sign(self, key: bytes, data: bytes) -> bytes:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def hmac_verify(self, key: bytes, data: bytes, tag: bytes) -> None:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(data)
        h.verify(tag)

    def sign(self, private_key: bytes, data: bytes) -> bytes:
        sk = x25519.X25519PrivateKey.from_private_bytes(private_key)
        return sk.sign(data)

    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None:
        pk = x25519.X25519PublicKey.from_public_bytes(public_key)
        try:
            pk.verify(signature, data)
        except InvalidSignature as e:
            raise e

    def hpke_seal(self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes) -> tuple[bytes, bytes]:
        hpke = HPKE(
            kem_id=KEM_ID.DHKEM_X25519_HKDF_SHA256,
            kdf_id=KDF_ID.HKDF_SHA256,
            aead_id=AEAD_ID.AES128_GCM,
        )
        pkR = x25519.X25519PublicKey.from_public_bytes(public_key)
        enc, ct = hpke.seal(pkR, info, aad, ptxt)
        return enc, ct

    def hpke_open(self, private_key: bytes, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes) -> bytes:
        hpke = HPKE(
            kem_id=KEM_ID.DHKEM_X25519_HKDF_SHA256,
            kdf_id=KDF_ID.HKDF_SHA256,
            aead_id=AEAD_ID.AES128_GCM,
        )
        skR = x25519.X25519PrivateKey.from_private_bytes(private_key)
        return hpke.open(skR, kem_output, info, aad, ctxt)

    def generate_key_pair(self) -> tuple[bytes, bytes]:
        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        return sk.private_bytes_raw(), pk.public_bytes_raw()

    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        sk = x25519.X25519PrivateKey.from_private_bytes(seed)
        pk = sk.public_key()
        return sk.private_bytes_raw(), pk.public_bytes_raw()

    def kem_pk_size(self) -> int:
        # For DHKEM(X25519), the public key size is 32 bytes.
        return 32

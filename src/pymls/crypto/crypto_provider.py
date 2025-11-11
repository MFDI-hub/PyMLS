from abc import ABC, abstractmethod
from .hpke import KEM, AEAD, KDF  # noqa: F401 (referenced in type hints and implementors)
from .ciphersuites import MlsCiphersuite


class CryptoProvider(ABC):
    @property
    @abstractmethod
    def supported_ciphersuites(self):
        pass

    @property
    @abstractmethod
    def active_ciphersuite(self) -> MlsCiphersuite:
        pass

    @abstractmethod
    def set_ciphersuite(self, suite_id: int) -> None:
        """
        Select the active MLS ciphersuite by its RFC suite id (see RFC 9420 §16.3).
        """
        pass

    @abstractmethod
    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        pass

    @abstractmethod
    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        pass

    @abstractmethod
    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        pass

    @abstractmethod
    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        pass

    @abstractmethod
    def hmac_sign(self, key: bytes, data: bytes) -> bytes:
        pass

    @abstractmethod
    def hmac_verify(self, key: bytes, data: bytes, tag: bytes) -> None:
        pass

    @abstractmethod
    def sign(self, private_key: bytes, data: bytes) -> bytes:
        pass

    @abstractmethod
    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None:
        pass

    @abstractmethod
    def hpke_seal(self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def hpke_open(self, private_key: bytes, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes) -> bytes:
        pass

    @abstractmethod
    def generate_key_pair(self) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        pass

    @abstractmethod
    def kem_pk_size(self) -> int:
        pass 

    @abstractmethod
    def aead_key_size(self) -> int:
        """
        Return the key size in bytes for the active AEAD.
        """
        pass

    @abstractmethod
    def aead_nonce_size(self) -> int:
        """
        Return the nonce size in bytes for the active AEAD.
        """
        pass

    @abstractmethod
    def kdf_hash_len(self) -> int:
        """
        Return the underlying hash length (bytes) for the active KDF.
        """
        pass
from abc import ABC, abstractmethod
from typing import NamedTuple, Protocol

from .hpke import KEM, AEAD, KDF


class CryptoProvider(ABC):
    @property
    @abstractmethod
    def supported_ciphersuites(self):
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
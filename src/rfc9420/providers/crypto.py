"""Protocol for cryptographic operations required by MLS (RFC 9420).

Implementations provide HPKE, AEAD, KDF, hashing, and signing. The existing
CryptoProvider ABC in rfc9420.crypto satisfies this protocol.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class CryptoProviderProtocol(Protocol):
    """Interface for all cryptographic operations required by RFC 9420.

    Implementations must provide ciphersuite selection, HKDF, hashing, AEAD,
    HMAC, signatures, and HPKE. Use rfc9420.crypto.DefaultCryptoProvider
    or a custom implementation.
    """

    @property
    def supported_ciphersuites(self):
        """Iterable of RFC ciphersuite ids supported by this provider.

        Returns
        -------
        Iterable
            Supported ciphersuite ids.
        """
        ...

    @property
    def active_ciphersuite(self):
        """Currently selected ciphersuite (MlsCiphersuite).

        Returns
        -------
        MlsCiphersuite
            Active ciphersuite.
        """
        ...

    def set_ciphersuite(self, suite_id: int) -> None:
        """Select the active MLS ciphersuite by RFC suite id.

        Parameters
        ----------
        suite_id : int
            RFC ciphersuite identifier.
        """
        ...

    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes: ...
    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes: ...
    def hash(self, data: bytes) -> bytes: ...
    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...
    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...
    def hmac_sign(self, key: bytes, data: bytes) -> bytes: ...
    def hmac_verify(self, key: bytes, data: bytes, tag: bytes) -> None: ...
    def sign(self, private_key: bytes, data: bytes) -> bytes: ...
    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None: ...
    def sign_with_label(self, private_key: bytes, label: bytes, content: bytes) -> bytes: ...
    def verify_with_label(
        self, public_key: bytes, label: bytes, content: bytes, signature: bytes
    ) -> None: ...
    def hpke_seal(
        self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes
    ) -> tuple[bytes, bytes]: ...
    def hpke_open(
        self,
        private_key: bytes,
        kem_output: bytes,
        info: bytes,
        aad: bytes,
        ctxt: bytes,
    ) -> bytes: ...
    def hpke_export_secret(
        self,
        private_key: bytes,
        kem_output: bytes,
        info: bytes,
        export_label: bytes,
        export_length: int,
    ) -> bytes: ...
    def hpke_seal_and_export(
        self,
        public_key: bytes,
        info: bytes,
        aad: bytes,
        ptxt: bytes,
        export_label: bytes,
        export_length: int,
    ) -> tuple[bytes, bytes, bytes]:
        """HPKE seal and export from sender context (RFC 9420 §8.3). Returns (kem_output, ciphertext, exported_secret)."""
        ...
    def generate_key_pair(self) -> tuple[bytes, bytes]: ...
    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]: ...
    def kem_sk_ikm_min_size(self) -> int:
        """Minimum size in bytes for IKM passed to derive_key_pair (e.g. Nsk for HPKE)."""
        ...
    def kem_pk_size(self) -> int: ...
    def aead_key_size(self) -> int: ...
    def aead_nonce_size(self) -> int: ...
    def kdf_hash_len(self) -> int: ...
    def expand_with_label(
        self, secret: bytes, label: bytes, context: bytes, length: int
    ) -> bytes: ...
    def derive_secret(self, secret: bytes, label: bytes) -> bytes: ...

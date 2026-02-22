"""Abstract cryptographic provider interface used by the protocol layer.

This module defines the CryptoProvider abstract base class, which specifies
all cryptographic operations required by MLS. Implementations must provide
concrete implementations for all abstract methods.

The CryptoProvider interface abstracts away the specific cryptographic library
used, allowing different backends (e.g., cryptography, OpenSSL bindings) to
be used interchangeably.
"""
from abc import ABC, abstractmethod
from .ciphersuites import MlsCiphersuite


class CryptoProvider(ABC):
    """Abstract interface for all cryptographic operations required by RFC9420.

    This class defines the interface that all cryptographic providers must
    implement. It includes methods for:
    - Ciphersuite management
    - Key derivation (HKDF)
    - Hashing
    - Authenticated encryption (AEAD)
    - HMAC operations
    - Digital signatures
    - HPKE operations
    - Key generation and derivation

    Subclasses should implement all abstract methods to provide concrete
    cryptographic functionality. See DefaultCryptoProvider for a reference
    implementation using the cryptography library.
    """
    @property
    @abstractmethod
    def supported_ciphersuites(self):
        """Iterable of RFC ciphersuite ids supported by this provider."""
        pass

    @property
    @abstractmethod
    def active_ciphersuite(self) -> MlsCiphersuite:
        """Currently selected ciphersuite."""
        pass

    @abstractmethod
    def set_ciphersuite(self, suite_id: int) -> None:
        """
        Select the active MLS ciphersuite by its RFC suite id (see RFC 9420 §16.3).
        """
        pass

    @abstractmethod
    def kdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract(salt, ikm) for the active KDF."""
        pass

    @abstractmethod
    def kdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand(prk, info, length) for the active KDF."""
        pass

    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        """Compute a direct hash of data using the ciphersuite's hash algorithm (RFC Hash)."""
        pass

    @abstractmethod
    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """AEAD seal."""
        pass

    @abstractmethod
    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """AEAD open."""
        pass

    @abstractmethod
    def hmac_sign(self, key: bytes, data: bytes) -> bytes:
        """Compute HMAC tag over data with key."""
        pass

    @abstractmethod
    def hmac_verify(self, key: bytes, data: bytes, tag: bytes) -> None:
        """Verify HMAC tag, raising on failure."""
        pass

    @abstractmethod
    def sign(self, private_key: bytes, data: bytes) -> bytes:
        """Sign data with the active signature scheme."""
        pass

    @abstractmethod
    def verify(self, public_key: bytes, data: bytes, signature: bytes) -> None:
        """Verify signature, raising on failure."""
        pass

    @abstractmethod
    def sign_with_label(self, private_key: bytes, label: bytes, content: bytes) -> bytes:
        """
        Domain-separated signing helper (RFC 9420 §5.1.2).
        Signs the serialization of:
            SignContent := struct { opaque label<V>; opaque content<V>; }
        where V is a TLS variable-length opaque vector.
        """
        pass

    @abstractmethod
    def verify_with_label(self, public_key: bytes, label: bytes, content: bytes, signature: bytes) -> None:
        """
        Domain-separated signature verification (RFC 9420 §5.1.2).
        Verifies signature over the serialized SignContent struct as above.
        """
        pass

    @abstractmethod
    def hpke_seal(self, public_key: bytes, info: bytes, aad: bytes, ptxt: bytes) -> tuple[bytes, bytes]:
        """HPKE seal: returns (enc, ciphertext)."""
        pass

    @abstractmethod
    def hpke_open(self, private_key: bytes, kem_output: bytes, info: bytes, aad: bytes, ctxt: bytes) -> bytes:
        """HPKE open: returns plaintext."""
        pass

    @abstractmethod
    def hpke_export_secret(self, private_key: bytes, kem_output: bytes, info: bytes, export_label: bytes, export_length: int) -> bytes:
        """HPKE SetupBaseR + Context.Export."""
        pass

    @abstractmethod
    def generate_key_pair(self) -> tuple[bytes, bytes]:
        """Generate a key pair for the active KEM's underlying curve/algorithm."""
        pass

    @abstractmethod
    def derive_key_pair(self, seed: bytes) -> tuple[bytes, bytes]:
        """Derive a deterministic key pair from a seed when supported."""
        pass

    @abstractmethod
    def kem_pk_size(self) -> int:
        """Size in bytes of the KEM public key encoding for stream parsing (if defined)."""
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

    # --- RFC 9420 labeled KDF helpers ---
    @abstractmethod
    def expand_with_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        """
        HKDF-Expand with RFC 9420 label formatting:
        info := uint16(length) || opaque8("MLS 1.0 " + label) || opaque16(context)
        """
        pass

    @abstractmethod
    def derive_secret(self, secret: bytes, label: bytes) -> bytes:
        """
        Convenience wrapper: expand_with_label(secret, label, context="", length=Hash.length)
        """
        pass
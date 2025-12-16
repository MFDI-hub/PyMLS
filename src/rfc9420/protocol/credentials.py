"""Credential encodings (basic and X.509) and signature scheme mapping."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import List

from ..codec.tls import (
    write_uint8,
    read_uint8,
    write_opaque16,
    read_opaque16,
)
from ..crypto.ciphersuites import SignatureScheme
from ..mls.exceptions import CredentialValidationError, UnsupportedCipherSuiteError


class CredentialType(IntEnum):
    """Wire identifier for credential variants."""
    BASIC = 1
    X509 = 2


def _encode_signature_scheme(s: SignatureScheme) -> bytes:
    """
    Compact on-the-wire encoding for signature scheme identifiers.
    Stable mapping for interop within this library.
    """
    mapping = {
        SignatureScheme.ED25519: 0x01,
        SignatureScheme.ED448: 0x02,
        SignatureScheme.ECDSA_SECP256R1_SHA256: 0x11,
        SignatureScheme.ECDSA_SECP521R1_SHA512: 0x12,
    }
    return write_uint8(mapping[s])


def _decode_signature_scheme(b: int) -> SignatureScheme:
    """Inverse of _encode_signature_scheme for reading from the wire."""
    reverse = {
        0x01: SignatureScheme.ED25519,
        0x02: SignatureScheme.ED448,
        0x11: SignatureScheme.ECDSA_SECP256R1_SHA256,
        0x12: SignatureScheme.ECDSA_SECP521R1_SHA512,
    }
    if b not in reverse:
        raise UnsupportedCipherSuiteError(f"Unknown signature scheme code: {b}")
    return reverse[b]


@dataclass(frozen=True)
class BasicCredential:
    """Simple credential binding identity and public key with a signature scheme."""
    identity: bytes
    public_key: bytes
    signature_scheme: SignatureScheme

    def serialize(self) -> bytes:
        """Encode as: type=BASIC || opaque16(identity) || opaque16(public_key) || scheme."""
        return (
            write_uint8(int(CredentialType.BASIC))
            + write_opaque16(self.identity)
            + write_opaque16(self.public_key)
            + _encode_signature_scheme(self.signature_scheme)
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "BasicCredential":
        """Parse BasicCredential from bytes produced by serialize()."""
        off = 0
        cred_type, off = read_uint8(data, off)
        if CredentialType(cred_type) != CredentialType.BASIC:
            raise CredentialValidationError("Not a Basic credential")
        identity, off = read_opaque16(data, off)
        public_key, off = read_opaque16(data, off)
        sig_code, off = read_uint8(data, off)
        return cls(identity, public_key, _decode_signature_scheme(sig_code))


@dataclass(frozen=True)
class X509Credential:
    """
    Minimal X.509 credential carrying a certificate chain.
    Signature scheme can be inferred from the end-entity cert if desired;
    we carry it explicitly here for simplicity.
    """

    cert_chain: List[bytes]
    signature_scheme: SignatureScheme

    def serialize(self) -> bytes:
        out = write_uint8(int(CredentialType.X509))
        out += write_uint8(len(self.cert_chain))
        for cert in self.cert_chain:
            out += write_opaque16(cert)
        out += _encode_signature_scheme(self.signature_scheme)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "X509Credential":
        off = 0
        cred_type, off = read_uint8(data, off)
        if CredentialType(cred_type) != CredentialType.X509:
            raise CredentialValidationError("Not an X.509 credential")
        num, off = read_uint8(data, off)
        chain: List[bytes] = []
        for _ in range(num):
            cert, off = read_opaque16(data, off)
            chain.append(cert)
        sig_code, off = read_uint8(data, off)
        return cls(chain, _decode_signature_scheme(sig_code))

    def verify_chain(self, trust_roots: List[bytes]) -> bytes:
        """
        Verify the certificate chain against the provided trust roots.
        Returns the leaf certificate's public key bytes on success.
        """
        from ..crypto.x509 import verify_certificate_chain
        return verify_certificate_chain(self.cert_chain, trust_roots)

    def verify_chain_with_policy(self, trust_roots: List[bytes], policy) -> bytes:
        """
        Verify the certificate chain and enforce an X.509 policy.
        Returns the leaf certificate's public key bytes on success.
        """
        from ..crypto.x509 import verify_certificate_chain_with_policy
        return verify_certificate_chain_with_policy(self.cert_chain, trust_roots, policy)




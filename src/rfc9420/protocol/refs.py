"""Hash-based references (RFC 9420 §5.2).

RefHashInput := struct { opaque label<V>; opaque value<V>; }
Serialization uses varint length prefixes per RFC 9420 §2.1.2.
Provides KeyPackageRef and ProposalRef computation for tree hashing and proposal references.
"""
from __future__ import annotations


from ..crypto import labels as mls_labels
from ..crypto.crypto_provider import CryptoProvider


def _encode_len_prefixed(b: bytes) -> bytes:
    from ..codec.tls import write_opaque_varint
    return write_opaque_varint(b or b"")


def encode_ref_hash_input(label: bytes, value: bytes) -> bytes:
    """Serialize RefHashInput (RFC 9420 §5.2): opaque label<V> || opaque value<V>.

    Parameters:
        label: Label (should include full RFC string, e.g. "MLS 1.0 KeyPackage Reference").
        value: Value to hash (e.g. serialized KeyPackage or Proposal).

    Returns:
        Serialized struct with varint length prefixes.
    """
    return _encode_len_prefixed(label or b"") + _encode_len_prefixed(value or b"")


def make_key_package_ref(crypto: CryptoProvider, value: bytes) -> bytes:
    """Compute KeyPackageRef as Hash(RefHashInput("MLS 1.0 KeyPackage Reference", value)).

    Parameters:
        crypto: Crypto provider (hash algorithm from active ciphersuite).
        value: Serialized KeyPackage (or value to reference).

    Returns:
        Hash digest (KeyPackageRef).
    """
    data = encode_ref_hash_input(mls_labels.REF_KEYPACKAGE, value)
    return crypto.hash(data)


def make_proposal_ref(crypto: CryptoProvider, value: bytes) -> bytes:
    """Compute ProposalRef as Hash(RefHashInput("MLS 1.0 Proposal Reference", value)).

    Parameters:
        crypto: Crypto provider (hash algorithm from active ciphersuite).
        value: Serialized Proposal (or value to reference).

    Returns:
        Hash digest (ProposalRef).
    """
    data = encode_ref_hash_input(mls_labels.REF_PROPOSAL, value)
    return crypto.hash(data)



"""Hash-based references (RFC 9420 §5.2).

RefHashInput := struct { opaque label<V>; opaque value<V>; }
Serialization uses varint length prefixes per RFC 9420 §2.1.2.
Provides KeyPackageRef and ProposalRef computation for tree hashing and proposal references.

KeyPackageRef MUST use a CryptoProvider for the KeyPackage's cipher suite.
ProposalRef MUST use the group's CryptoProvider.
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

    RFC 9420 §5.2: the hash algorithm is determined by the cipher suite specified
    in the KeyPackage. Callers MUST pass a CryptoProvider configured with that
    KeyPackage's cipher suite (not the group's), so the correct hash is used.

    Parameters:
        crypto: Crypto provider whose active ciphersuite MUST match the KeyPackage's
            (hash algorithm from that suite is used).
        value: Serialized KeyPackage (encoded KeyPackage per RFC).

    Returns:
        Hash digest (KeyPackageRef).
    """
    data = encode_ref_hash_input(mls_labels.REF_KEYPACKAGE, value)
    return crypto.hash(data)


def make_proposal_ref(crypto: CryptoProvider, value: bytes) -> bytes:
    """Compute ProposalRef as Hash(RefHashInput("MLS 1.0 Proposal Reference", value)).

    RFC 9420 §5.2: the value is the AuthenticatedContent carrying the Proposal;
    the hash algorithm is determined by the group's cipher suite. Callers MUST
    pass the group's CryptoProvider.

    Parameters:
        crypto: Crypto provider for the group (hash algorithm from group ciphersuite).
        value: Serialized AuthenticatedContent carrying the Proposal (not just the
            Proposal bytes).

    Returns:
        Hash digest (ProposalRef).
    """
    data = encode_ref_hash_input(mls_labels.REF_PROPOSAL, value)
    return crypto.hash(data)



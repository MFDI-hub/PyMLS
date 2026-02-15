"""
Hash-based references (RFC 9420 §5.2).

RefHashInput := struct { opaque label<V>; opaque value<V>; }
We serialize with 4-byte length prefixes to align with existing helpers.
"""
from __future__ import annotations

import struct
from ..crypto import labels as mls_labels
from ..crypto.crypto_provider import CryptoProvider


def _encode_len_prefixed(b: bytes) -> bytes:
    return struct.pack("!H", len(b)) + (b or b"")


def encode_ref_hash_input(label: bytes, value: bytes) -> bytes:
    """
    Serialize RefHashInput with the provided label and value.
    Label should include the full string required by RFC (including 'MLS 1.0 ').
    """
    return _encode_len_prefixed(label or b"") + _encode_len_prefixed(value or b"")


def make_key_package_ref(crypto: CryptoProvider, value: bytes) -> bytes:
    """
    Compute a KeyPackageRef as Hash(RefHashInput("MLS 1.0 KeyPackage Reference", value)).
    """
    data = encode_ref_hash_input(mls_labels.REF_KEYPACKAGE, value)
    return crypto.hash(data)


def make_proposal_ref(crypto: CryptoProvider, value: bytes) -> bytes:
    """
    Compute a ProposalRef as Hash(RefHashInput("MLS 1.0 Proposal Reference", value)).
    """
    data = encode_ref_hash_input(mls_labels.REF_PROPOSAL, value)
    return crypto.hash(data)



"""MLS protocol structure encoding/decoding for interop and wire I/O.

This module provides functions to serialize and deserialize MLS core structures
(Welcome, Commit, Proposal) according to RFC 9420 wire format specifications.
Used by the interop harness and by the API layer for handshake/application framing.
"""
from __future__ import annotations
from typing import List, Tuple
import struct

from ..protocol.data_structures import (
    Welcome,
    Commit,
    Proposal,
    Signature,
    serialize_bytes,
    deserialize_bytes,
)


def encode_welcome(welcome: Welcome) -> bytes:
    """Encode a Welcome message to RFC 9420 §12.4.3.1 wire format.

    Parameters:
        welcome: Welcome message structure to serialize.

    Returns:
        Serialized Welcome message bytes.
    """
    return welcome.serialize()


def decode_welcome(data: bytes) -> Welcome:
    """Decode a Welcome message from RFC 9420 §12.4.3.1 wire format.

    Parameters:
        data: Serialized Welcome message bytes.

    Returns:
        Parsed Welcome message structure.
    """
    return Welcome.deserialize(data)


def encode_commit_message(commit: Commit, signature: bytes) -> bytes:
    """Encode a Commit message to RFC 9420 §12.4 wire format.

    The signature is appended after the serialized Commit content (Commit
    structure does not hold the signature; it is serialized separately).

    Parameters:
        commit: Commit structure to serialize.
        signature: Signature bytes to append after the Commit content.

    Returns:
        Serialized Commit message bytes (Commit content + signature).
    """
    # Create a new Commit without signature (Commit structure doesn't hold it)
    updated_commit = Commit(
        path=commit.path,
        proposals=commit.proposals,
    )
    # Serialize Commit content + Signature
    return updated_commit.serialize() + Signature(signature).serialize()


def decode_commit_message(data: bytes) -> Tuple[Commit, bytes]:
    """Decode a Commit message from RFC 9420 §12.4 wire format.

    Parameters:
        data: Serialized Commit message bytes (Commit content followed by signature).

    Returns:
        Tuple of (parsed Commit structure, signature bytes).
    """
    commit = Commit.deserialize(data)
    commit_len = len(commit.serialize())
    from ..protocol.data_structures import Signature
    signature = Signature.deserialize(data[commit_len:])
    return (commit, signature.value)


def encode_proposals_message(proposals: List[Proposal], signature: bytes) -> bytes:
    """Encode a list of Proposal messages to RFC 9420 §12.4 wire format.

    Serializes proposals as a vector (uint16 count + opaque<V> per proposal).
    The signature parameter is ignored; it is kept for API compatibility.

    Parameters:
        proposals: List of Proposal structures to serialize.
        signature: Ignored (kept for API compatibility).

    Returns:
        Serialized proposals vector bytes.
    """
    # Serialize as a vector: uint16(len) || serialize_bytes(proposal.serialize()) for each
    data = struct.pack("!H", len(proposals))
    for proposal in proposals:
        proposal_bytes = proposal.serialize()
        data += serialize_bytes(proposal_bytes)
    return data


def decode_proposals_message(data: bytes) -> Tuple[List[Proposal], bytes]:
    """Decode a list of Proposal messages from RFC 9420 §12.4 wire format.

    Parameters:
        data: Serialized proposals vector bytes (uint16 count + opaque<V> per proposal).

    Returns:
        Tuple of (parsed list of Proposal structures, empty signature bytes).
    """
    if len(data) < 2:
        return ([], b"")
    
    num_proposals, = struct.unpack("!H", data[:2])
    rest = data[2:]
    proposals: List[Proposal] = []
    
    for _ in range(num_proposals):
        proposal_bytes, rest = deserialize_bytes(rest)
        proposal = Proposal.deserialize(proposal_bytes)
        proposals.append(proposal)
    
    return (proposals, b"")


"""MLS protocol structure encoding/decoding for interop harness.

This module provides functions to serialize and deserialize MLS core structures
(Welcome, Commit, Proposal) according to RFC 9420 wire format specifications.
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
    
    Parameters
    ----------
    welcome : Welcome
        Welcome message structure to serialize.
    
    Returns
    -------
    bytes
        Serialized Welcome message bytes.
    """
    return welcome.serialize()


def decode_welcome(data: bytes) -> Welcome:
    """Decode a Welcome message from RFC 9420 §12.4.3.1 wire format.
    
    Parameters
    ----------
    data : bytes
        Serialized Welcome message bytes.
    
    Returns
    -------
    Welcome
        Parsed Welcome message structure.
    """
    return Welcome.deserialize(data)


def encode_commit_message(commit: Commit, signature: bytes) -> bytes:
    """Encode a Commit message to RFC 9420 §12.4 wire format.
    
    The signature parameter is used to create a new Commit with the provided
    signature bytes, replacing the existing signature in the commit object.
    
    Parameters
    ----------
    commit : Commit
        Commit structure to serialize.
    signature : bytes
        Signature bytes to use in the serialized Commit.
    
    Returns
    -------
    bytes
        Serialized Commit message bytes.
    """
    # Create a new Commit with the provided signature
    updated_commit = Commit(
        path=commit.path,
        proposals=commit.proposals,
        signature=Signature(signature)
    )
    return updated_commit.serialize()


def decode_commit_message(data: bytes) -> Tuple[Commit, bytes]:
    """Decode a Commit message from RFC 9420 §12.4 wire format.
    
    Parameters
    ----------
    data : bytes
        Serialized Commit message bytes.
    
    Returns
    -------
    Tuple[Commit, bytes]
        Tuple of (parsed Commit structure, signature bytes).
    """
    commit = Commit.deserialize(data)
    return (commit, commit.signature.value)


def encode_proposals_message(proposals: List[Proposal], signature: bytes) -> bytes:
    """Encode a list of Proposal messages to RFC 9420 §12.4 wire format.
    
    Serializes proposals as a vector following the format used in Commit structures.
    The signature parameter is ignored (proposals don't have signatures in this context).
    
    Parameters
    ----------
    proposals : List[Proposal]
        List of Proposal structures to serialize.
    signature : bytes
        Ignored parameter (kept for API compatibility).
    
    Returns
    -------
    bytes
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
    
    Parameters
    ----------
    data : bytes
        Serialized proposals vector bytes.
    
    Returns
    -------
    Tuple[List[Proposal], bytes]
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


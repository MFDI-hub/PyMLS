"""Minimal internal wire encoding for MLS messages used by this library.

This module defines a lightweight, temporary wire format for MLS messages
that is sufficient for inter-module communication inside this project. It
is intentionally simpler than the standard MLS wire types and may be
superseded as the implementation matures.

Wire Layouts
- MLSMessage:
  - uint8 content_type (see MLSContentType)
  - opaque24 body (message-specific payload)
  - opaque16 signature (detached signature over canonical content)

High-level helpers are provided to encode/decode commits, proposals, and
welcome messages to/from this internal format.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Tuple

from .tls import (
    write_uint8,
    read_uint8,
    write_opaque16,
    read_opaque16,
    write_opaque24,
    read_opaque24,
)
from ..protocol.data_structures import Proposal, Commit, Welcome
from ..mls.exceptions import PyMLSError


class MLSContentType(IntEnum):
    """Enumerates the types of MLS message bodies supported by this module.

    Values
    - PROPOSAL (1): Body contains a vector of encoded proposals.
    - COMMIT (2): Body contains an encoded commit object.
    """
    PROPOSAL = 1
    COMMIT = 2


@dataclass
class MLSMessage:
    """Container for the minimal internal MLS wire message format.

    Fields
    - content_type: Indicates how to interpret 'body' (see MLSContentType).
    - body: Message-specific payload encoded as bytes.
    - signature: Detached signature over the canonical content of the message.
      The signature scheme and verification are handled by higher layers.
    """
    content_type: MLSContentType
    body: bytes
    signature: bytes

    def serialize(self) -> bytes:
        """Serialize the MLSMessage into the internal wire format.

        Returns
        - Bytes consisting of: uint8 content_type, opaque24 body, opaque16 signature.

        Notes
        - Uses TLS-like helpers for length-prefixing (see codec.tls).
        """
        # Minimal internal wire format (will be superseded by standard MLS wire types):
        #  uint8 content_type
        #  opaque24 body
        #  opaque16 signature
        return (
            write_uint8(int(self.content_type))
            + write_opaque24(self.body)
            + write_opaque16(self.signature)
        )

    @classmethod
    def deserialize(cls, data: bytes) -> "MLSMessage":
        """Parse an MLSMessage from the internal wire format.

        Parameters
        - data: Bytes encoded by MLSMessage.serialize().

        Returns
        - A new MLSMessage instance.

        Raises
        - TLSDecodeError (from codec.tls): If the buffer is too short.
        - ValueError: If the content_type byte cannot be mapped to MLSContentType.
        """
        ct_val, off = read_uint8(data, 0)
        body, off = read_opaque24(data, off)
        sig, off = read_opaque16(data, off)
        return cls(MLSContentType(ct_val), body, sig)


def encode_commit_message(commit: Commit, signature: bytes) -> bytes:
    """Encode a Commit and signature into the internal MLSMessage format.

    Parameters
    - commit: Commit object providing a serialize() method.
    - signature: Detached signature bytes to include in the message.

    Returns
    - Bytes of the serialized MLSMessage.
    """
    msg = MLSMessage(MLSContentType.COMMIT, commit.serialize(), signature)
    return msg.serialize()


def decode_commit_message(data: bytes) -> Tuple[Commit, bytes]:
    """Decode a commit MLSMessage into its structured components.

    Parameters
    - data: Bytes previously returned by encode_commit_message().

    Returns
    - (commit, signature) where 'commit' is a Commit instance and 'signature'
      is the detached signature bytes.

    Raises
    - PyMLSError: If the content type is not COMMIT.
    - TLSDecodeError (from codec.tls): If the buffer is too short.
    """
    msg = MLSMessage.deserialize(data)
    if msg.content_type != MLSContentType.COMMIT:
        raise PyMLSError("Not a COMMIT MLSMessage")
    return Commit.deserialize(msg.body), msg.signature


def encode_proposals_message(proposals: List[Proposal], signature: bytes) -> bytes:
    """Encode a vector of proposals and signature as an MLSMessage.

    Internal body layout:
      body := uint16 num_proposals + num_proposals * opaque16(proposal_bytes)

    Parameters
    - proposals: List of Proposal objects; each must provide serialize().
    - signature: Detached signature bytes to include.

    Returns
    - Bytes of the serialized MLSMessage with content_type=PROPOSAL.
    """
    # body := uint16 num + repeated opaque16 proposal
    from .tls import write_uint16

    body = write_uint16(len(proposals))
    for p in proposals:
        body += write_opaque16(p.serialize())
    msg = MLSMessage(MLSContentType.PROPOSAL, body, signature)
    return msg.serialize()


def decode_proposals_message(data: bytes) -> Tuple[List[Proposal], bytes]:
    """Decode a proposals MLSMessage into structured proposals and signature.

    Parameters
    - data: Bytes previously returned by encode_proposals_message().

    Returns
    - (proposals, signature) where 'proposals' is a list of Proposal objects.

    Raises
    - PyMLSError: If the content type is not PROPOSAL.
    - TLSDecodeError (from codec.tls): If the buffer is too short.
    """
    from .tls import read_uint16

    msg = MLSMessage.deserialize(data)
    if msg.content_type != MLSContentType.PROPOSAL:
        raise PyMLSError("Not a PROPOSAL MLSMessage")

    off = 0
    num, off = read_uint16(msg.body, off)
    out: List[Proposal] = []
    for _ in range(num):
        item, off = read_opaque16(msg.body, off)
        out.append(Proposal.deserialize(item))
    return out, msg.signature


def encode_welcome(welcome: Welcome) -> bytes:
    """Encode a Welcome object into its wire representation.

    Parameters
    - welcome: Welcome object providing serialize().

    Returns
    - Raw bytes as produced by Welcome.serialize().
    """
    return welcome.serialize()


def decode_welcome(data: bytes) -> Welcome:
    """Decode a Welcome object from its wire representation.

    Parameters
    - data: Bytes previously produced by encode_welcome() or Welcome.serialize().

    Returns
    - A Welcome instance parsed from the provided bytes.
    """
    return Welcome.deserialize(data)


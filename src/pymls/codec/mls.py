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


class MLSContentType(IntEnum):
    PROPOSAL = 1
    COMMIT = 2


@dataclass
class MLSMessage:
    content_type: MLSContentType
    body: bytes
    signature: bytes

    def serialize(self) -> bytes:
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
        ct_val, off = read_uint8(data, 0)
        body, off = read_opaque24(data, off)
        sig, off = read_opaque16(data, off)
        return cls(MLSContentType(ct_val), body, sig)


def encode_commit_message(commit: Commit, signature: bytes) -> bytes:
    msg = MLSMessage(MLSContentType.COMMIT, commit.serialize(), signature)
    return msg.serialize()


def decode_commit_message(data: bytes) -> Tuple[Commit, bytes]:
    msg = MLSMessage.deserialize(data)
    if msg.content_type != MLSContentType.COMMIT:
        raise ValueError("Not a COMMIT MLSMessage")
    return Commit.deserialize(msg.body), msg.signature


def encode_proposals_message(proposals: List[Proposal], signature: bytes) -> bytes:
    # body := uint16 num + repeated opaque16 proposal
    from .tls import write_uint16

    body = write_uint16(len(proposals))
    for p in proposals:
        body += write_opaque16(p.serialize())
    msg = MLSMessage(MLSContentType.PROPOSAL, body, signature)
    return msg.serialize()


def decode_proposals_message(data: bytes) -> Tuple[List[Proposal], bytes]:
    from .tls import read_uint16

    msg = MLSMessage.deserialize(data)
    if msg.content_type != MLSContentType.PROPOSAL:
        raise ValueError("Not a PROPOSAL MLSMessage")

    off = 0
    num, off = read_uint16(msg.body, off)
    out: List[Proposal] = []
    for _ in range(num):
        item, off = read_opaque16(msg.body, off)
        out.append(Proposal.deserialize(item))
    return out, msg.signature


def encode_welcome(welcome: Welcome) -> bytes:
    return welcome.serialize()


def decode_welcome(data: bytes) -> Welcome:
    return Welcome.deserialize(data)


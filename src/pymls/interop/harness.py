from __future__ import annotations

"""
Interop harness scaffolding.

These helpers serialize/deserialize MLS core structures using PyMLS codecs.
External interop (OpenMLS/MLS++) can be added by invoking their CLIs/FFI here.
"""

from typing import Tuple, List

from ..codec.mls import (
    encode_commit_message,
    decode_commit_message,
    encode_proposals_message,
    decode_proposals_message,
    encode_welcome,
    decode_welcome,
)
from ..protocol.data_structures import Commit, Proposal, Welcome


def round_trip_commit(commit: Commit, signature: bytes) -> Tuple[Commit, bytes]:
    data = encode_commit_message(commit, signature)
    return decode_commit_message(data)


def round_trip_proposals(proposals: List[Proposal], signature: bytes) -> Tuple[List[Proposal], bytes]:
    data = encode_proposals_message(proposals, signature)
    return decode_proposals_message(data)


def round_trip_welcome(welcome: Welcome) -> Welcome:
    data = encode_welcome(welcome)
    return decode_welcome(data)



from __future__ import annotations

"""
Interop harness scaffolding.

These helpers serialize/deserialize MLS core structures using PyMLS codecs.
External interop (OpenMLS/MLS++) can be added by invoking their CLIs/FFI here.
"""

from typing import Tuple, List
import base64

from ..codec.mls import (
    encode_commit_message,
    decode_commit_message,
    encode_proposals_message,
    decode_proposals_message,
    encode_welcome,
    decode_welcome,
)
from ..protocol.data_structures import Commit, Proposal, Welcome
from ..protocol.messages import MLSPlaintext, MLSCiphertext
from ..protocol.messages import ContentType as WireContentType
from .wire import encode_handshake, decode_handshake, encode_application, decode_application



def round_trip_commit(commit: Commit, signature: bytes) -> Tuple[Commit, bytes]:
    data = encode_commit_message(commit, signature)
    return decode_commit_message(data)


def round_trip_proposals(proposals: List[Proposal], signature: bytes) -> Tuple[List[Proposal], bytes]:
    data = encode_proposals_message(proposals, signature)
    return decode_proposals_message(data)


def round_trip_welcome(welcome: Welcome) -> Welcome:
    data = encode_welcome(welcome)
    return decode_welcome(data)


def export_plaintext_hex(m: MLSPlaintext) -> str:
    return m.serialize().hex()


def import_plaintext_hex(h: str) -> MLSPlaintext:
    data = bytes.fromhex(h)
    return MLSPlaintext.deserialize(data)


def export_ciphertext_hex(m: MLSCiphertext) -> str:
    return m.serialize().hex()


def import_ciphertext_hex(h: str) -> MLSCiphertext:
    data = bytes.fromhex(h)
    return MLSCiphertext.deserialize(data)

# --- Base64 RFC wire helpers ---
def export_handshake_b64(m: MLSPlaintext) -> str:
    return base64.b64encode(encode_handshake(m)).decode("ascii")


def import_handshake_b64(s: str) -> MLSPlaintext:
    return decode_handshake(base64.b64decode(s.encode("ascii")))


def export_application_b64(m: MLSCiphertext) -> str:
    return base64.b64encode(encode_application(m)).decode("ascii")


def import_application_b64(s: str) -> MLSCiphertext:
    return decode_application(base64.b64decode(s.encode("ascii")))


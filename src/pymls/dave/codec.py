from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple, List, Literal, Union, Dict, Any

from ..codec.tls import (
    write_uint8,
    write_uint16,
    write_opaque24,
    read_uint8,
    read_uint16,
    read_opaque24,
)
from ..codec.mls import (
    encode_commit_message,
    decode_commit_message,
    encode_proposals_message,
    decode_proposals_message,
    encode_welcome,
    decode_welcome,
)
from ..protocol.key_packages import KeyPackage
from ..protocol.data_structures import Proposal, Commit, Welcome

# Adapters stay compatible with legacy minimal MLSMessage framing used by DAVE.
# New RFC framing (MLSPlaintext/MLSCiphertext) is available in protocol.messages.


# DAVE Voice Gateway opcodes used by the DAVE MLS layer
OP_DAVE_PROTOCOL_PREPARE_TRANSITION = 21  # JSON
OP_DAVE_PROTOCOL_EXECUTE_TRANSITION = 22  # JSON
OP_DAVE_PROTOCOL_READY_FOR_TRANSITION = 23  # JSON
OP_DAVE_PROTOCOL_PREPARE_EPOCH = 24  # JSON
OP_DAVE_MLS_EXTERNAL_SENDER_PACKAGE = 25  # binary
OP_DAVE_MLS_KEY_PACKAGE = 26  # binary
OP_DAVE_MLS_PROPOSALS = 27  # binary (MLSMessage(Proposals))
OP_DAVE_MLS_COMMIT_WELCOME = 28  # binary (union Commit or Welcome)
OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION = 29  # binary (MLSMessage(Commit))
OP_DAVE_MLS_WELCOME = 30  # binary (Welcome)
OP_DAVE_MLS_INVALID_COMMIT_WELCOME = 31  # JSON


def _pack_binary(opcode: int, sequence_number: int, body: bytes) -> bytes:
    return write_uint16(sequence_number) + write_uint8(opcode) + body


def _unpack_binary(buf: bytes, offset: int = 0) -> Tuple[int, int, int]:
    """
    Returns (sequence_number, opcode, next_offset)
    """
    seq, off = read_uint16(buf, offset)
    opcode, off = read_uint8(buf, off)
    return seq, opcode, off


# JSON opcode helpers
def make_json(opcode: int, d: Dict[str, Any]) -> Dict[str, Any]:
    return {"op": opcode, "d": d}


# 25: external sender package (opaque payload, binary)
def pack_external_sender_package(sequence_number: int, package_bytes: bytes) -> bytes:
    body = write_opaque24(package_bytes)
    return _pack_binary(OP_DAVE_MLS_EXTERNAL_SENDER_PACKAGE, sequence_number, body)


def unpack_external_sender_package(buf: bytes, offset: int = 0) -> Tuple[int, bytes, int]:
    seq, opcode, off = _unpack_binary(buf, offset)
    if opcode != OP_DAVE_MLS_EXTERNAL_SENDER_PACKAGE:
        raise ValueError("unexpected opcode for external sender package")
    package, off = read_opaque24(buf, off)
    return seq, package, off


# 26: key package (binary)
def pack_key_package(sequence_number: int, kp: KeyPackage) -> bytes:
    body = write_opaque24(kp.serialize())
    return _pack_binary(OP_DAVE_MLS_KEY_PACKAGE, sequence_number, body)


def unpack_key_package(buf: bytes, offset: int = 0) -> Tuple[int, KeyPackage, int]:
    seq, opcode, off = _unpack_binary(buf, offset)
    if opcode != OP_DAVE_MLS_KEY_PACKAGE:
        raise ValueError("unexpected opcode for key package")
    data, off = read_opaque24(buf, off)
    return seq, KeyPackage.deserialize(data), off


# 27: proposals (binary MLSMessage(Proposals))
def pack_proposals(sequence_number: int, proposals: List[Proposal], signature: bytes) -> bytes:
    body = write_opaque24(encode_proposals_message(proposals, signature))
    return _pack_binary(OP_DAVE_MLS_PROPOSALS, sequence_number, body)


def unpack_proposals(buf: bytes, offset: int = 0) -> Tuple[int, List[Proposal], bytes, int]:
    seq, opcode, off = _unpack_binary(buf, offset)
    if opcode != OP_DAVE_MLS_PROPOSALS:
        raise ValueError("unexpected opcode for proposals")
    payload, off = read_opaque24(buf, off)
    proposals, sig = decode_proposals_message(payload)
    return seq, proposals, sig, off


# 28: commit/welcome union (binary)
# kind = 0 => Commit (MLSMessage(Commit))
# kind = 1 => Welcome
def pack_commit_or_welcome(
    sequence_number: int,
    transition_id: int,
    kind: Literal[0, 1],
    payload: Union[Tuple[Commit, bytes], Welcome],
):
    body = write_uint16(transition_id) + write_uint8(kind)
    if kind == 0:
        commit, signature = payload  # type: ignore[assignment]
        body += write_opaque24(encode_commit_message(commit, signature))
    else:
        welcome = payload  # type: ignore[assignment]
        body += write_opaque24(encode_welcome(welcome))
    return _pack_binary(OP_DAVE_MLS_COMMIT_WELCOME, sequence_number, body)


def unpack_commit_or_welcome(buf: bytes, offset: int = 0) -> Tuple[int, int, Literal[0, 1], Union[Tuple[Commit, bytes], Welcome], int]:
    seq, opcode, off = _unpack_binary(buf, offset)
    if opcode != OP_DAVE_MLS_COMMIT_WELCOME:
        raise ValueError("unexpected opcode for commit/welcome")
    transition_id, off = read_uint16(buf, off)
    kind, off = read_uint8(buf, off)
    data, off = read_opaque24(buf, off)
    if kind == 0:
        commit, sig = decode_commit_message(data)
        payload: Union[Tuple[Commit, bytes], Welcome] = (commit, sig)
    else:
        payload = decode_welcome(data)
    return seq, transition_id, kind, payload, off


# 29: announce commit transition (binary)
def pack_announce_commit(sequence_number: int, transition_id: int, commit: Commit, signature: bytes) -> bytes:
    body = write_uint16(transition_id) + write_opaque24(encode_commit_message(commit, signature))
    return _pack_binary(OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION, sequence_number, body)


def unpack_announce_commit(buf: bytes, offset: int = 0) -> Tuple[int, int, Commit, bytes, int]:
    seq, opcode, off = _unpack_binary(buf, offset)
    if opcode != OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION:
        raise ValueError("unexpected opcode for announce commit transition")
    transition_id, off = read_uint16(buf, off)
    payload, off = read_opaque24(buf, off)
    commit, sig = decode_commit_message(payload)
    return seq, transition_id, commit, sig, off


# 30: welcome (binary)
def pack_welcome(sequence_number: int, transition_id: int, welcome: Welcome) -> bytes:
    body = write_uint16(transition_id) + write_opaque24(encode_welcome(welcome))
    return _pack_binary(OP_DAVE_MLS_WELCOME, sequence_number, body)


def unpack_welcome(buf: bytes, offset: int = 0) -> Tuple[int, int, Welcome, int]:
    seq, opcode, off = _unpack_binary(buf, offset)
    if opcode != OP_DAVE_MLS_WELCOME:
        raise ValueError("unexpected opcode for welcome")
    transition_id, off = read_uint16(buf, off)
    payload, off = read_opaque24(buf, off)
    return seq, transition_id, decode_welcome(payload), off



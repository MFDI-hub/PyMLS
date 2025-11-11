from __future__ import annotations

from dataclasses import dataclass


class TLSDecodeError(Exception):
    pass


def _require_length(buf: bytes, need: int) -> None:
    if len(buf) < need:
        raise TLSDecodeError(f"buffer too short: need {need}, have {len(buf)}")


def write_uint8(x: int) -> bytes:
    return bytes((x & 0xFF,))


def write_uint16(x: int) -> bytes:
    return ((x >> 8) & 0xFF).to_bytes(1, "big") + (x & 0xFF).to_bytes(1, "big")


def write_uint24(x: int) -> bytes:
    return bytes(((x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF))


def write_uint32(x: int) -> bytes:
    return x.to_bytes(4, "big")


def read_uint8(buf: bytes, offset: int = 0) -> tuple[int, int]:
    _require_length(buf[offset:], 1)
    return buf[offset], offset + 1


def read_uint16(buf: bytes, offset: int = 0) -> tuple[int, int]:
    _require_length(buf[offset:], 2)
    return int.from_bytes(buf[offset:offset + 2], "big"), offset + 2


def read_uint24(buf: bytes, offset: int = 0) -> tuple[int, int]:
    _require_length(buf[offset:], 3)
    val = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
    return val, offset + 3


def read_uint32(buf: bytes, offset: int = 0) -> tuple[int, int]:
    _require_length(buf[offset:], 4)
    return int.from_bytes(buf[offset:offset + 4], "big"), offset + 4


def write_vector(data: bytes, length_bytes: int) -> bytes:
    if length_bytes not in (1, 2, 3):
        raise ValueError("length_bytes must be 1, 2, or 3")

    length = len(data)
    if length_bytes == 1:
        if length > 0xFF:
            raise ValueError("vector too long for 1-byte length")
        return write_uint8(length) + data
    if length_bytes == 2:
        if length > 0xFFFF:
            raise ValueError("vector too long for 2-byte length")
        return write_uint16(length) + data

    # length_bytes == 3
    if length > 0xFFFFFF:
        raise ValueError("vector too long for 3-byte length")
    return write_uint24(length) + data


def read_vector(buf: bytes, offset: int, length_bytes: int) -> tuple[bytes, int]:
    if length_bytes == 1:
        length, offset = read_uint8(buf, offset)
    elif length_bytes == 2:
        length, offset = read_uint16(buf, offset)
    elif length_bytes == 3:
        length, offset = read_uint24(buf, offset)
    else:
        raise ValueError("length_bytes must be 1, 2, or 3")

    _require_length(buf[offset:], length)
    return buf[offset:offset + length], offset + length


def write_opaque8(data: bytes) -> bytes:
    return write_vector(data, 1)


def write_opaque16(data: bytes) -> bytes:
    return write_vector(data, 2)


def write_opaque24(data: bytes) -> bytes:
    return write_vector(data, 3)


def read_opaque8(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    return read_vector(buf, offset, 1)


def read_opaque16(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    return read_vector(buf, offset, 2)


def read_opaque24(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    return read_vector(buf, offset, 3)


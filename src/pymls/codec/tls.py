"""TLS-like integer and length-prefixed vector encoding helpers.

This module provides a minimal subset of TLS-style serialization utilities
used throughout the project for encoding and decoding primitive integer
types and length-prefixed byte vectors. All multi-byte integers are encoded
in big-endian (network) byte order.

Conventions
- "write_*" functions return encoded bytes for the given value.
- "read_*" functions take a buffer and an offset, and return a tuple of
  (decoded_value, new_offset). They raise TLSDecodeError if the buffer
  does not contain enough data starting at the given offset.
- Vector helpers implement TLS-style opaque vectors with 1-, 2-, or 3-byte
  length prefixes (opaque8/16/24).
"""
from __future__ import annotations

from dataclasses import dataclass


class TLSDecodeError(Exception):
    """Raised when decoding fails due to insufficient or malformed input."""


def _require_length(buf: bytes, need: int) -> None:
    """Ensure that the provided buffer contains at least 'need' bytes.

    Parameters
    - buf: Bytes-like object to check.
    - need: Minimum number of bytes required.

    Raises
    - TLSDecodeError: If len(buf) < need.
    """
    if len(buf) < need:
        raise TLSDecodeError(f"buffer too short: need {need}, have {len(buf)}")


def write_uint8(x: int) -> bytes:
    """Encode an unsigned 8-bit integer in big-endian format.

    Parameters
    - x: Integer in range [0, 255].

    Returns
    - Encoded single-byte representation.
    """
    return bytes((x & 0xFF,))


def write_uint16(x: int) -> bytes:
    """Encode an unsigned 16-bit integer in big-endian format.

    Parameters
    - x: Integer in range [0, 65535].

    Returns
    - 2-byte big-endian encoding.
    """
    return ((x >> 8) & 0xFF).to_bytes(1, "big") + (x & 0xFF).to_bytes(1, "big")


def write_uint24(x: int) -> bytes:
    """Encode an unsigned 24-bit integer in big-endian format.

    Parameters
    - x: Integer in range [0, 2^24 - 1].

    Returns
    - 3-byte big-endian encoding.
    """
    return bytes(((x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF))


def write_uint32(x: int) -> bytes:
    """Encode an unsigned 32-bit integer in big-endian format.

    Parameters
    - x: Integer in range [0, 2^32 - 1].

    Returns
    - 4-byte big-endian encoding.
    """
    return x.to_bytes(4, "big")


def write_uint64(x: int) -> bytes:
    """Encode an unsigned 64-bit integer in big-endian format.

    Parameters
    - x: Integer in range [0, 2^64 - 1].

    Returns
    - 8-byte big-endian encoding.
    """
    return x.to_bytes(8, "big")


def read_uint8(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 8-bit integer from buf starting at offset.

    Parameters
    - buf: Source bytes.
    - offset: Starting index within buf.

    Returns
    - (value, new_offset) where new_offset = offset + 1.

    Raises
    - TLSDecodeError: If insufficient bytes are available.
    """
    _require_length(buf[offset:], 1)
    return buf[offset], offset + 1


def read_uint16(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 16-bit integer from buf starting at offset.

    Parameters
    - buf: Source bytes.
    - offset: Starting index within buf.

    Returns
    - (value, new_offset) where new_offset = offset + 2.

    Raises
    - TLSDecodeError: If insufficient bytes are available.
    """
    _require_length(buf[offset:], 2)
    return int.from_bytes(buf[offset:offset + 2], "big"), offset + 2


def read_uint24(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 24-bit integer from buf starting at offset.

    Parameters
    - buf: Source bytes.
    - offset: Starting index within buf.

    Returns
    - (value, new_offset) where new_offset = offset + 3.

    Raises
    - TLSDecodeError: If insufficient bytes are available.
    """
    _require_length(buf[offset:], 3)
    val = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
    return val, offset + 3


def read_uint32(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 32-bit integer from buf starting at offset.

    Parameters
    - buf: Source bytes.
    - offset: Starting index within buf.

    Returns
    - (value, new_offset) where new_offset = offset + 4.

    Raises
    - TLSDecodeError: If insufficient bytes are available.
    """
    _require_length(buf[offset:], 4)
    return int.from_bytes(buf[offset:offset + 4], "big"), offset + 4


def read_uint64(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 64-bit integer from buf starting at offset.

    Parameters
    - buf: Source bytes.
    - offset: Starting index within buf.

    Returns
    - (value, new_offset) where new_offset = offset + 8.

    Raises
    - TLSDecodeError: If insufficient bytes are available.
    """
    _require_length(buf[offset:], 8)
    return int.from_bytes(buf[offset:offset + 8], "big"), offset + 8


def write_vector(data: bytes, length_bytes: int) -> bytes:
    """Encode a TLS-style opaque vector with a length prefix.

    Parameters
    - data: The payload to prefix with its length.
    - length_bytes: Number of bytes to encode the length (1, 2, or 3).

    Returns
    - Encoded bytes consisting of length prefix followed by data.

    Raises
    - ValueError: If length_bytes is not 1, 2, or 3, or if data is too long
      for the chosen length size.
    """
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
    """Decode a TLS-style opaque vector with a length prefix.

    Parameters
    - buf: Source bytes containing the vector.
    - offset: Starting index within buf.
    - length_bytes: Number of bytes used to encode the length (1, 2, or 3).

    Returns
    - (data, new_offset) where data is the extracted payload and new_offset
      points to the first byte following the payload.

    Raises
    - ValueError: If length_bytes is not 1, 2, or 3.
    - TLSDecodeError: If insufficient bytes are available for length or data.
    """
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
    """Encode an opaque vector with an 8-bit length prefix."""
    return write_vector(data, 1)


def write_opaque16(data: bytes) -> bytes:
    """Encode an opaque vector with a 16-bit length prefix."""
    return write_vector(data, 2)


def write_opaque24(data: bytes) -> bytes:
    """Encode an opaque vector with a 24-bit length prefix."""
    return write_vector(data, 3)


def read_opaque8(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with an 8-bit length prefix."""
    return read_vector(buf, offset, 1)


def read_opaque16(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with a 16-bit length prefix."""
    return read_vector(buf, offset, 2)


def read_opaque24(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with a 24-bit length prefix."""
    return read_vector(buf, offset, 3)


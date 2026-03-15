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
- Vector helpers implement TLS-style opaque vectors with 1-, 2-, 3-, or 4-byte
  length prefixes (opaque8/16/24/32), plus RFC 9420 §2.1.2 varint-prefixed
  opaque vectors (opaque_varint).
- Optional value encoding (RFC 9420 §2.1.1): write_optional / read_optional
  use a presence octet (0 = absent, 1 = present) followed by the value encoding
  when present.
"""

from __future__ import annotations

from typing import Callable, TypeVar
from ..mls.exceptions import MalformedMessageError

T = TypeVar("T")


class TLSDecodeError(MalformedMessageError):
    """Raised when decoding fails due to insufficient or malformed input."""


def _require_length(buf: bytes, need: int) -> None:
    """Ensure that the provided buffer contains at least 'need' bytes.

    Parameters
    ----------
    buf : bytes
        Bytes-like object to check.
    need : int
        Minimum number of bytes required.

    Raises
    ------
    TLSDecodeError
        If len(buf) < need.
    """
    if len(buf) < need:
        raise TLSDecodeError(f"buffer too short: need {need}, have {len(buf)}")


def write_uint8(x: int) -> bytes:
    """Encode an unsigned 8-bit integer in big-endian format.

    Parameters
    ----------
    x : int
        Integer in range [0, 255].

    Returns
    -------
    bytes
        Encoded single-byte representation.
    """
    return bytes((x & 0xFF,))


def write_uint16(x: int) -> bytes:
    """Encode an unsigned 16-bit integer in big-endian format.

    Parameters
    ----------
    x : int
        Integer in range [0, 65535].

    Returns
    -------
    bytes
        2-byte big-endian encoding.
    """
    return ((x >> 8) & 0xFF).to_bytes(1, "big") + (x & 0xFF).to_bytes(1, "big")


def write_uint24(x: int) -> bytes:
    """Encode an unsigned 24-bit integer in big-endian format.

    Parameters
    ----------
    x : int
        Integer in range [0, 2^24 - 1].

    Returns
    -------
    bytes
        3-byte big-endian encoding.
    """
    return bytes(((x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF))


def write_uint32(x: int) -> bytes:
    """Encode an unsigned 32-bit integer in big-endian format.

    Parameters
    ----------
    x : int
        Integer in range [0, 2^32 - 1].

    Returns
    -------
    bytes
        4-byte big-endian encoding.
    """
    return x.to_bytes(4, "big")


def write_uint64(x: int) -> bytes:
    """Encode an unsigned 64-bit integer in big-endian format.

    Parameters
    ----------
    x : int
        Integer in range [0, 2^64 - 1].

    Returns
    -------
    bytes
        8-byte big-endian encoding.
    """
    return x.to_bytes(8, "big")


def read_uint8(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 8-bit integer from buf starting at offset.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index within buf (default 0).

    Returns
    -------
    tuple[int, int]
        (value, new_offset) where new_offset = offset + 1.

    Raises
    ------
    TLSDecodeError
        If insufficient bytes are available.
    """
    _require_length(buf[offset:], 1)
    return buf[offset], offset + 1


def read_uint16(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 16-bit integer from buf starting at offset.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index within buf (default 0).

    Returns
    -------
    tuple[int, int]
        (value, new_offset) where new_offset = offset + 2.

    Raises
    ------
    TLSDecodeError
        If insufficient bytes are available.
    """
    _require_length(buf[offset:], 2)
    return int.from_bytes(buf[offset : offset + 2], "big"), offset + 2


def read_uint24(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 24-bit integer from buf starting at offset.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index within buf (default 0).

    Returns
    -------
    tuple[int, int]
        (value, new_offset) where new_offset = offset + 3.

    Raises
    ------
    TLSDecodeError
        If insufficient bytes are available.
    """
    _require_length(buf[offset:], 3)
    val = (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2]
    return val, offset + 3


def read_uint32(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 32-bit integer from buf starting at offset.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index within buf (default 0).

    Returns
    -------
    tuple[int, int]
        (value, new_offset) where new_offset = offset + 4.

    Raises
    ------
    TLSDecodeError
        If insufficient bytes are available.
    """
    _require_length(buf[offset:], 4)
    return int.from_bytes(buf[offset : offset + 4], "big"), offset + 4


def read_uint64(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode an unsigned 64-bit integer from buf starting at offset.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index within buf (default 0).

    Returns
    -------
    tuple[int, int]
        (value, new_offset) where new_offset = offset + 8.

    Raises
    ------
    TLSDecodeError
        If insufficient bytes are available.
    """
    _require_length(buf[offset:], 8)
    return int.from_bytes(buf[offset : offset + 8], "big"), offset + 8


def write_vector(data: bytes, length_bytes: int) -> bytes:
    """Encode a TLS-style opaque vector with a length prefix.

    Parameters
    ----------
    data : bytes
        The payload to prefix with its length.
    length_bytes : int
        Number of bytes to encode the length (1, 2, or 3).

    Returns
    -------
    bytes
        Encoded bytes consisting of length prefix followed by data.

    Raises
    ------
    ValueError
        If length_bytes is not 1, 2, or 3, or if data is too long for the chosen length size.
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
    ----------
    buf : bytes
        Source bytes containing the vector.
    offset : int
        Starting index within buf.
    length_bytes : int
        Number of bytes used to encode the length (1, 2, 3, or 4).

    Returns
    -------
    tuple[bytes, int]
        (data, new_offset) where data is the extracted payload and new_offset
        points to the first byte following the payload.

    Raises
    ------
    ValueError
        If length_bytes is not 1, 2, 3, or 4.
    TLSDecodeError
        If insufficient bytes are available for length or data.
    """
    if length_bytes == 1:
        length, offset = read_uint8(buf, offset)
    elif length_bytes == 2:
        length, offset = read_uint16(buf, offset)
    elif length_bytes == 3:
        length, offset = read_uint24(buf, offset)
    elif length_bytes == 4:
        length, offset = read_uint32(buf, offset)
    else:
        raise ValueError("length_bytes must be 1, 2, 3, or 4")

    _require_length(buf[offset:], length)
    return buf[offset : offset + length], offset + length


def write_opaque8(data: bytes) -> bytes:
    """Encode an opaque vector with an 8-bit length prefix (max 255 bytes).

    Parameters
    ----------
    data : bytes
        Payload to encode.

    Returns
    -------
    bytes
        Length-prefixed bytes (1-byte length + data).
    """
    return write_vector(data, 1)


def write_opaque16(data: bytes) -> bytes:
    """Encode an opaque vector with a 16-bit length prefix (max 65535 bytes).

    Parameters
    ----------
    data : bytes
        Payload to encode.

    Returns
    -------
    bytes
        Length-prefixed bytes (2-byte length + data).
    """
    return write_vector(data, 2)


def write_opaque24(data: bytes) -> bytes:
    """Encode an opaque vector with a 24-bit length prefix (max 2^24 - 1 bytes).

    Parameters
    ----------
    data : bytes
        Payload to encode.

    Returns
    -------
    bytes
        Length-prefixed bytes (3-byte length + data).
    """
    return write_vector(data, 3)


def write_opaque32(data: bytes) -> bytes:
    """Encode an opaque vector with a 32-bit (uint32) length prefix.

    Parameters
    ----------
    data : bytes
        Payload to encode.

    Returns
    -------
    bytes
        Length-prefixed bytes (4-byte length + data).
    """
    return write_uint32(len(data)) + data


def read_opaque8(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with an 8-bit length prefix.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index (default 0).

    Returns
    -------
    tuple[bytes, int]
        (payload, new_offset) where new_offset points past the decoded vector.

    Raises
    ------
    TLSDecodeError
        If the buffer is too short for the length or payload.
    """
    return read_vector(buf, offset, 1)


def read_opaque16(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with a 16-bit length prefix.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index (default 0).

    Returns
    -------
    tuple[bytes, int]
        (payload, new_offset) where new_offset points past the decoded vector.

    Raises
    ------
    TLSDecodeError
        If the buffer is too short for the length or payload.
    """
    return read_vector(buf, offset, 2)


def read_opaque24(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with a 24-bit length prefix.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index (default 0).

    Returns
    -------
    tuple[bytes, int]
        (payload, new_offset) where new_offset points past the decoded vector.

    Raises
    ------
    TLSDecodeError
        If the buffer is too short for the length or payload.
    """
    return read_vector(buf, offset, 3)


def read_opaque32(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with a 32-bit (uint32) length prefix.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index (default 0).

    Returns
    -------
    tuple[bytes, int]
        (payload, new_offset) where new_offset points past the decoded vector.

    Raises
    ------
    TLSDecodeError
        If the buffer is too short for the length or payload.
    """
    return read_vector(buf, offset, 4)


# --- RFC 9000 Variable-Length Integer Encoding (Varint) ---


def write_varint(x: int) -> bytes:
    """Encode an integer using RFC 9420 §2.1.2 variable-length encoding.

    RFC 9420 Table 1: prefix 11 is invalid; only 1-, 2-, and 4-byte encodings
    are used. Max value is 2^30 - 1 (1073741823).

    Encoding rules (x is the value, len is length in bytes):
    - x in [0, 63]: len=1, prefix 00
    - x in [64, 16383]: len=2, prefix 01
    - x in [16384, 1073741823]: len=4, prefix 10

    Parameters
    ----------
    x : int
        Integer to encode.

    Returns
    -------
    bytes
        Encoded bytes.

    Raises
    ------
    ValueError
        If x is out of range.
    """
    if x < 0:
        raise ValueError("varint cannot be negative")
    if x < 0x40:
        return bytes([x])
    if x < 0x4000:
        return (x | 0x4000).to_bytes(2, "big")
    if x <= 0x3FFFFFFF:  # 2^30 - 1
        return (x | 0x80000000).to_bytes(4, "big")
    raise ValueError("integer too large for RFC 9420 varint encoding (max 2^30-1)")


def read_varint(buf: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode RFC 9420 §2.1.2 variable-length integer.

    Prefix 11 is invalid and MUST be rejected. Minimum-length encoding
    is required (from RFC 9000): values that fit in fewer bytes must not
    use a longer encoding.

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index (default 0).

    Returns
    -------
    tuple[int, int]
        (value, new_offset).

    Raises
    ------
    TLSDecodeError
        If buffer too short, prefix is 11, or encoding is not minimum-length.
    """
    _require_length(buf[offset:], 1)
    first = buf[offset]
    prefix = first >> 6
    if prefix == 3:
        raise TLSDecodeError("invalid variable-length integer prefix 11 (RFC 9420)")
    length = 1 << prefix

    available = len(buf) - offset
    if available < length:
        raise TLSDecodeError(
            f"truncated varint at offset {offset}: need {length} bytes for encoded varint, have {available}"
        )
    val_bytes = buf[offset : offset + length]
    val = int.from_bytes(val_bytes, "big")
    if length == 1:
        val &= 0x3F
    elif length == 2:
        val &= 0x3FFF
        if val < 0x40:
            raise TLSDecodeError("varint minimum encoding required (value < 64 must use 1 byte)")
    elif length == 4:
        val &= 0x3FFFFFFF
        if val < 0x4000:
            raise TLSDecodeError(
                "varint minimum encoding required (value < 16384 must use 1 or 2 bytes)"
            )
    else:
        raise TLSDecodeError("invalid varint length")
    return val, offset + length


def write_opaque_varint(data: bytes) -> bytes:
    """Encode an opaque vector with a Varint length prefix (RFC 9420 §2.1.2 <V>).

    Parameters
    ----------
    data : bytes
        Payload to encode.

    Returns
    -------
    bytes
        Varint length prefix plus data bytes.
    """
    return write_varint(len(data)) + data


def read_opaque_varint(buf: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Decode an opaque vector with a Varint length prefix (RFC 9420 §2.1.2).

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int, optional
        Starting index (default 0).

    Returns
    -------
    tuple[bytes, int]
        (payload, new_offset) where new_offset points past the decoded vector.

    Raises
    ------
    TLSDecodeError
        If the buffer is too short or length exceeds available bytes.
    """
    length, offset = read_varint(buf, offset)
    available = len(buf) - offset
    if available < length:
        raise TLSDecodeError(
            f"opaque<V> length overflow at offset {offset}: declared length {length}, available {available}"
        )
    return buf[offset : offset + length], offset + length


# --- RFC 9420 §2.1.1 Optional Value ---


def write_optional(
    value: T | None,
    encode_fn: Callable[[T], bytes],
) -> bytes:
    """Encode an optional value per RFC 9420 §2.1.1.

    Presence octet: 0 = absent, 1 = present. If present, the encoding of the
    value follows (produced by encode_fn(value)).

    Parameters
    ----------
    value : T or None
        The value to encode, or None for absent.
    encode_fn : Callable[[T], bytes]
        Callable that takes the value and returns its encoded bytes.

    Returns
    -------
    bytes
        Encoded bytes (presence octet plus value encoding when present).
    """
    if value is None:
        return write_uint8(0)
    return write_uint8(1) + encode_fn(value)


def read_optional(
    buf: bytes,
    offset: int,
    decode_fn: Callable[[bytes, int], tuple[T, int]],
) -> tuple[T | None, int]:
    """Decode an optional value per RFC 9420 §2.1.1.

    Reads the presence octet at offset; if 0 returns (None, offset+1). If 1,
    decodes the value using decode_fn(buf, offset+1) and returns (value, new_offset).
    Any other presence value raises TLSDecodeError (RFC 9420 §2.1.1: must be 0 or 1).

    Parameters
    ----------
    buf : bytes
        Source bytes.
    offset : int
        Starting index (at the presence octet).
    decode_fn : Callable[[bytes, int], tuple[T, int]]
        Callable (buffer, start_offset) -> (decoded_value, new_offset).

    Returns
    -------
    tuple[T | None, int]
        (decoded_value or None, new_offset).

    Raises
    ------
    TLSDecodeError
        If buffer too short or presence octet not 0 or 1.
    """
    _require_length(buf[offset:], 1)
    present = buf[offset]
    if present == 0:
        return None, offset + 1
    if present != 1:
        raise TLSDecodeError(
            f"invalid optional value presence octet at offset {offset}: {present} (RFC 9420 §2.1.1: must be 0 or 1)"
        )
    return decode_fn(buf, offset + 1)

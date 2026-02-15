"""Encoding helpers and simple constructors for MLS extensions (MVP set)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple

from ..codec.tls import (
    write_uint16,
    write_opaque16,
    read_uint16,
    read_opaque16,
)


class ExtensionType(IntEnum):
    """Extension type identifiers per RFC 9420 §17.3 IANA registry.

    Values 0x0001–0x0005 are from RFC 9420 Table 9.
    Values 0x000A–0x000D follow common interop conventions.
    Values 0xFF00+ are private-use / implementation-specific.
    """
    # RFC 9420 Table 9 (IANA-registered)
    APPLICATION_ID = 0x0001
    RATCHET_TREE = 0x0002
    REQUIRED_CAPABILITIES = 0x0003
    EXTERNAL_PUB = 0x0004
    EXTERNAL_SENDERS = 0x0005
    # Standard LeafNode extensions (interop conventions)
    # Note: These use private-use values (0xFFxx) as they are not standardized in RFC 9420 IANA registry.
    CAPABILITIES = 0xFF02   # Private-use: no IANA-assigned value for LeafNode capabilities
    LIFETIME = 0xFF03       # Private-use: no IANA-assigned value for LeafNode lifetime
    KEY_ID = 0xFF04         # Private-use: no IANA-assigned value for external key ID
    PARENT_HASH = 0xFF05    # Private-use: no IANA-assigned value for parent hash
    # Implementation-specific (private-use range)
    SUPPORTED_VERSIONS = 0xFF00
    EPOCH_AUTHENTICATOR = 0xFF01


@dataclass(frozen=True)
class Extension:
    """Generic extension: (type, opaque data)."""
    ext_type: ExtensionType
    data: bytes

    def serialize(self) -> bytes:
        """Encode as uint16(type) || opaque16(data)."""
        return write_uint16(int(self.ext_type)) + write_opaque16(self.data)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["Extension", int]:
        """Parse an Extension from the beginning of data and return (ext, bytes_used)."""
        off = 0
        t, off = read_uint16(data, off)
        body, off = read_opaque16(data, off)
        return cls(ExtensionType(t), body), off


def serialize_extensions(exts: list[Extension]) -> bytes:
    """Encode a vector of extensions as uint16(count) followed by entries."""
    out = write_uint16(len(exts))
    for e in exts:
        out += e.serialize()
    return out


def deserialize_extensions(data: bytes) -> list[Extension]:
    """Parse a vector of extensions encoded by serialize_extensions()."""
    off = 0
    num, off = read_uint16(data, off)
    out: list[Extension] = []
    for _ in range(num):
        e, used = Extension.deserialize(data[off:])
        out.append(e)
        off += used
    return out


def make_parent_hash_ext(parent_hash: bytes) -> Extension:
    """Build a PARENT_HASH extension from the provided parent hash bytes."""
    return Extension(ExtensionType.PARENT_HASH, parent_hash)


def make_capabilities_ext(data: bytes) -> Extension:
    """Build a CAPABILITIES extension with pre-encoded capability data."""
    return Extension(ExtensionType.CAPABILITIES, data)


def make_key_id_ext(key_id: bytes) -> Extension:
    """Build a KEY_ID extension wrapping an opaque identifier."""
    return Extension(ExtensionType.KEY_ID, key_id)


def make_lifetime_ext(not_before: int, not_after: int) -> Extension:
    """Build a LIFETIME extension from not_before/not_after unix timestamps."""
    from ..codec.tls import write_uint64
    payload = write_uint64(not_before) + write_uint64(not_after)
    return Extension(ExtensionType.LIFETIME, payload)


def parse_lifetime_ext(data: bytes) -> tuple[int, int]:
    """Parse LIFETIME extension payload into (not_before, not_after) timestamps."""
    from ..codec.tls import read_uint64
    off = 0
    nb, off = read_uint64(data, off)
    na, off = read_uint64(data, off)
    return nb, na


def make_external_pub_ext(public_key: bytes) -> Extension:
    """Build an EXTERNAL_PUB extension carrying a public key bytes value."""
    return Extension(ExtensionType.EXTERNAL_PUB, public_key)


def parse_external_pub_ext(data: bytes) -> bytes:
    """Return the raw EXTERNAL_PUB payload (identity function)."""
    return data


def build_capabilities_data(ciphersuite_ids: list[int], supported_exts: list[ExtensionType]) -> bytes:
    """Encode capabilities as vectors of ciphersuite ids and extension types."""
    from ..codec.tls import write_uint16
    out = write_uint16(len(ciphersuite_ids))
    for cs in ciphersuite_ids:
        out += write_uint16(cs)
    out += write_uint16(len(supported_exts))
    for e in supported_exts:
        out += write_uint16(int(e))
    return out


def parse_capabilities_data(data: bytes) -> tuple[list[int], list[ExtensionType]]:
    """Decode capabilities payload into (ciphersuite_ids, extension_types)."""
    from ..codec.tls import read_uint16
    off = 0
    num_cs, off = read_uint16(data, off)
    cs_ids: list[int] = []
    for _ in range(num_cs):
        cs, off = read_uint16(data, off)
        cs_ids.append(cs)
    num_ext, off = read_uint16(data, off)
    exts: list[ExtensionType] = []
    for _ in range(num_ext):
        t, off = read_uint16(data, off)
        exts.append(ExtensionType(t))
    return cs_ids, exts


def build_required_capabilities(exts_required: list[ExtensionType]) -> bytes:
    """Encode REQUIRED_CAPABILITIES as a vector of extension types."""
    from ..codec.tls import write_uint16
    out = write_uint16(len(exts_required))
    for e in exts_required:
        out += write_uint16(int(e))
    return out


def parse_required_capabilities(data: bytes) -> list[ExtensionType]:
    """Decode REQUIRED_CAPABILITIES payload into a list of ExtensionType."""
    from ..codec.tls import read_uint16
    off = 0
    num, off = read_uint16(data, off)
    out: list[ExtensionType] = []
    for _ in range(num):
        t, off = read_uint16(data, off)
        out.append(ExtensionType(t))
    return out



from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Dict, Tuple, Type

from ..codec.tls import (
    write_uint16,
    write_opaque16,
    read_uint16,
    read_opaque16,
)


class ExtensionType(IntEnum):
    CAPABILITIES = 1
    LIFETIME = 2
    KEY_ID = 3
    PARENT_HASH = 4
    RATCHET_TREE = 5
    EXTERNAL_PUB = 6


@dataclass(frozen=True)
class Extension:
    ext_type: ExtensionType
    data: bytes

    def serialize(self) -> bytes:
        return write_uint16(int(self.ext_type)) + write_opaque16(self.data)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["Extension", int]:
        off = 0
        t, off = read_uint16(data, off)
        body, off = read_opaque16(data, off)
        return cls(ExtensionType(t), body), off


def serialize_extensions(exts: list[Extension]) -> bytes:
    out = write_uint16(len(exts))
    for e in exts:
        out += e.serialize()
    return out


def deserialize_extensions(data: bytes) -> list[Extension]:
    off = 0
    num, off = read_uint16(data, off)
    out: list[Extension] = []
    for _ in range(num):
        e, used = Extension.deserialize(data[off:])
        out.append(e)
        off += used
    return out


def make_parent_hash_ext(parent_hash: bytes) -> Extension:
    return Extension(ExtensionType.PARENT_HASH, parent_hash)


def make_capabilities_ext(data: bytes) -> Extension:
    return Extension(ExtensionType.CAPABILITIES, data)


def make_key_id_ext(key_id: bytes) -> Extension:
    return Extension(ExtensionType.KEY_ID, key_id)


def make_lifetime_ext(not_before: int, not_after: int) -> Extension:
    from ..codec.tls import write_uint64
    payload = write_uint64(not_before) + write_uint64(not_after)
    return Extension(ExtensionType.LIFETIME, payload)


def parse_lifetime_ext(data: bytes) -> tuple[int, int]:
    from ..codec.tls import read_uint64
    off = 0
    nb, off = read_uint64(data, off)
    na, off = read_uint64(data, off)
    return nb, na


def make_external_pub_ext(public_key: bytes) -> Extension:
    return Extension(ExtensionType.EXTERNAL_PUB, public_key)


def parse_external_pub_ext(data: bytes) -> bytes:
    return data


def build_capabilities_data(ciphersuite_ids: list[int], supported_exts: list[ExtensionType]) -> bytes:
    from ..codec.tls import write_uint16
    out = write_uint16(len(ciphersuite_ids))
    for cs in ciphersuite_ids:
        out += write_uint16(cs)
    out += write_uint16(len(supported_exts))
    for e in supported_exts:
        out += write_uint16(int(e))
    return out


def parse_capabilities_data(data: bytes) -> tuple[list[int], list[ExtensionType]]:
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



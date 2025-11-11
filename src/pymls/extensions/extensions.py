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



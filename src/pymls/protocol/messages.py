from dataclasses import dataclass
import struct

from .data_structures import Signature


@dataclass(frozen=True)
class PublicMessage:
    content: bytes
    signature: Signature

    def serialize(self) -> bytes:
        return self.content + self.signature.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "PublicMessage":
        # This is a simplification
        content = data[:-64]
        signature = Signature.deserialize(data[-64:])
        return cls(content, signature)


@dataclass(frozen=True)
class PrivateMessage:
    ciphertext: bytes
    auth_tag: bytes

    def serialize(self) -> bytes:
        return self.ciphertext + self.auth_tag

    @classmethod
    def deserialize(cls, data: bytes) -> "PrivateMessage":
        # This is a simplification
        ciphertext = data[:-16]
        auth_tag = data[-16:]
        return cls(ciphertext, auth_tag)

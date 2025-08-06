from dataclasses import dataclass
import struct

from .data_structures import Credential, Signature, serialize_bytes, deserialize_bytes


@dataclass(frozen=True)
class LeafNode:
    encryption_key: bytes
    signature_key: bytes
    credential: Credential
    capabilities: bytes

    def serialize(self) -> bytes:
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        data += serialize_bytes(self.credential.serialize())
        data += serialize_bytes(self.capabilities)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "LeafNode":
        enc_key, rest = deserialize_bytes(data)
        sig_key, rest = deserialize_bytes(rest)
        cred_bytes, rest = deserialize_bytes(rest)
        credential = Credential.deserialize(cred_bytes)
        caps, _ = deserialize_bytes(rest)
        return cls(enc_key, sig_key, credential, caps)


@dataclass(frozen=True)
class KeyPackage:
    leaf_node: LeafNode
    signature: Signature

    def serialize(self) -> bytes:
        ln_bytes = self.leaf_node.serialize()
        return struct.pack("!I", len(ln_bytes)) + ln_bytes + self.signature.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyPackage":
        len_ln, = struct.unpack("!I", data[:4])
        ln_bytes = data[4:4+len_ln]
        sig_bytes = data[4+len_ln:]

        leaf_node = LeafNode.deserialize(ln_bytes)
        signature = Signature.deserialize(sig_bytes)
        return cls(leaf_node, signature)

    def verify(self, crypto_provider) -> None:
        crypto_provider.verify(
            self.leaf_node.signature_key,
            self.leaf_node.serialize(),
            self.signature.value
        )

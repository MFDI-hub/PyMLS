from dataclasses import dataclass
import struct

from .data_structures import Credential, Signature, serialize_bytes, deserialize_bytes


@dataclass(frozen=True)
class LeafNode:
    encryption_key: bytes
    signature_key: bytes
    credential: Credential
    capabilities: bytes
    parent_hash: bytes = b""

    def serialize(self) -> bytes:
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        data += serialize_bytes(self.credential.serialize())
        data += serialize_bytes(self.capabilities)
        data += serialize_bytes(self.parent_hash)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "LeafNode":
        # Backward-compatible: parent_hash is optional (absent in old encoding)
        enc_key, rest = deserialize_bytes(data)
        sig_key, rest = deserialize_bytes(rest)
        cred_bytes, rest = deserialize_bytes(rest)
        credential = Credential.deserialize(cred_bytes)
        caps, rest = deserialize_bytes(rest)
        parent_hash = b""
        try:
            parent_hash, rest2 = deserialize_bytes(rest)
            # If extra trailing bytes exist, ignore safely
            _ = rest2
        except Exception:
            parent_hash = b""
        return cls(enc_key, sig_key, credential, caps, parent_hash)


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

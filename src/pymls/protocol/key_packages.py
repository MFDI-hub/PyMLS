"""LeafNode and KeyPackage structures with basic (de)serialization and verification."""
from dataclasses import dataclass
import struct

from .data_structures import Credential, Signature, serialize_bytes, deserialize_bytes
from ..mls.exceptions import InvalidSignatureError


@dataclass(frozen=True)
class LeafNode:
    """Leaf node contents embedded in a KeyPackage.

    Fields
    - encryption_key: Public key used for HPKE encryption.
    - signature_key: Public key used for signature verification.
    - credential: Credential binding identity to signature_key.
    - capabilities: Opaque capabilities payload (extension-friendly).
    - parent_hash: Optional binding to parent nodes (MVP simplified).
    """
    encryption_key: bytes
    signature_key: bytes
    credential: Credential
    capabilities: bytes
    parent_hash: bytes = b""

    def serialize(self) -> bytes:
        """Encode fields as len-delimited blobs in a fixed order."""
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        data += serialize_bytes(self.credential.serialize())
        data += serialize_bytes(self.capabilities)
        data += serialize_bytes(self.parent_hash)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "LeafNode":
        """Parse a LeafNode from bytes produced by serialize().

        Backward compatibility
        - The parent_hash field is optional; if absent, it defaults to empty.
        """
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
    """A member's join artifact including a signed LeafNode."""
    leaf_node: LeafNode
    signature: Signature

    def serialize(self) -> bytes:
        """Encode as uint32(len(leaf_node)) || leaf_node || raw signature bytes."""
        ln_bytes = self.leaf_node.serialize()
        return struct.pack("!I", len(ln_bytes)) + ln_bytes + self.signature.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyPackage":
        """Parse KeyPackage from bytes produced by serialize()."""
        len_ln, = struct.unpack("!I", data[:4])
        ln_bytes = data[4:4+len_ln]
        sig_bytes = data[4+len_ln:]

        leaf_node = LeafNode.deserialize(ln_bytes)
        signature = Signature.deserialize(sig_bytes)
        return cls(leaf_node, signature)

    def verify(self, crypto_provider) -> None:
        """Verify the KeyPackage signature and credential consistency.

        Ensures that the credential public key matches the leaf's signature_key,
        then verifies the signature over the serialized LeafNode.
        """
        # Ensure credential public key matches the leaf signature key
        if self.leaf_node.credential.public_key != self.leaf_node.signature_key:
            raise InvalidSignatureError("credential public key does not match leaf signature key")
        crypto_provider.verify(
            self.leaf_node.signature_key,
            self.leaf_node.serialize(),
            self.signature.value
        )

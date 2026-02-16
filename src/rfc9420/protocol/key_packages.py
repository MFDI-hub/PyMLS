"""LeafNode and KeyPackage structures with basic (de)serialization and verification."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional
import struct

from .data_structures import (
    Credential,
    Signature,
    serialize_bytes,
    deserialize_bytes,
    MLSVersion,
    CipherSuite,
)
from ..crypto.ciphersuites import KEM, KDF, AEAD
from ..mls.exceptions import InvalidSignatureError
from ..extensions.extensions import (
    Extension,
    serialize_extensions,
    deserialize_extensions,
    make_capabilities_ext,
)


class LeafNodeSource(IntEnum):
    """Origin of the LeafNode per RFC §7.2 (simplified)."""

    KEY_PACKAGE = 1
    UPDATE = 2


@dataclass(frozen=True)
class LeafNode:
    """Leaf node contents embedded in a KeyPackage (RFC 9420 §7.2).

    Fields
    - encryption_key: HPKEPublicKey
    - signature_key: SignaturePublicKey
    - credential: Credential
    - capabilities: Capabilities
    - leaf_node_source: LeafNodeSource
    - extensions: Extensions
    - signature: Signature (covers LeafNodeTBS)
    """

    encryption_key: bytes
    signature_key: bytes
    credential: Optional[Credential]
    capabilities: bytes
    leaf_node_source: LeafNodeSource = LeafNodeSource.KEY_PACKAGE
    extensions: list[Extension] = None  # type: ignore[assignment]
    signature: bytes = b""
    parent_hash: bytes = b""  # Internal/MVP: kept for compatibility if needed, but not in RFC wire format for Source=KeyPackage?
    # RFC 9420 §7.2: parent_hash is conditional on source. 
    # KeyPackage source (1) -> no parent_hash. 
    # Update source (2) -> parent_hash.
    
    def serialize(self) -> bytes:
        """Encode fields per RFC 9420 §7.2."""
        if self.extensions is None:
            exts: list[Extension] = []
        else:
            exts = self.extensions
        # If legacy capabilities provided, also mirror it as an extension for RFC-compat
        if self.capabilities:
            try:
                cap_ext = make_capabilities_ext(self.capabilities)
                if not any(e.ext_type == cap_ext.ext_type for e in exts):
                    exts = exts + [cap_ext]
            except Exception:
                pass
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        cred_bytes = self.credential.serialize() if self.credential is not None else b""
        data += serialize_bytes(cred_bytes)
        data += serialize_bytes(self.capabilities)
        data += struct.pack("!B", int(self.leaf_node_source))
        if self.leaf_node_source == LeafNodeSource.UPDATE:
             data += serialize_bytes(self.parent_hash)
        data += serialize_bytes(serialize_extensions(exts))
        data += serialize_bytes(self.signature)
        return data

    def tbs_serialize(self) -> bytes:
        """Encode LeafNodeTBS (everything except signature) for signing."""
        # Same as serialize but without the last signature field
        if self.extensions is None:
            exts: list[Extension] = []
        else:
            exts = self.extensions
        if self.capabilities:
            try:
                cap_ext = make_capabilities_ext(self.capabilities)
                if not any(e.ext_type == cap_ext.ext_type for e in exts):
                    exts = exts + [cap_ext]
            except Exception:
                pass
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        cred_bytes = self.credential.serialize() if self.credential is not None else b""
        data += serialize_bytes(cred_bytes)
        data += serialize_bytes(self.capabilities)
        data += struct.pack("!B", int(self.leaf_node_source))
        if self.leaf_node_source == LeafNodeSource.UPDATE:
             data += serialize_bytes(self.parent_hash)
        data += serialize_bytes(serialize_extensions(exts))
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "LeafNode":
        """Parse a LeafNode from bytes produced by serialize()."""
        # Try full RFC parse
        try:
            enc_key, rest = deserialize_bytes(data)
            sig_key, rest = deserialize_bytes(rest)
            cred_bytes, rest = deserialize_bytes(rest)
            credential = Credential.deserialize(cred_bytes) if cred_bytes else None
            caps, rest = deserialize_bytes(rest)
            (src_val,) = struct.unpack("!B", rest[:1])
            leaf_source = LeafNodeSource(src_val)
            rest = rest[1:]
            parent_hash = b""
            if leaf_source == LeafNodeSource.UPDATE:
                 parent_hash, rest = deserialize_bytes(rest)
            exts_bytes, rest = deserialize_bytes(rest)
            extensions = deserialize_extensions(exts_bytes)
            signature, rest = deserialize_bytes(rest)
            return cls(
                encryption_key=enc_key,
                signature_key=sig_key,
                credential=credential,
                capabilities=caps,
                leaf_node_source=leaf_source,
                extensions=extensions,
                signature=signature,
                parent_hash=parent_hash
            )
        except Exception:
             # Parse failed
             raise


@dataclass(frozen=True)
class KeyPackage:
    """A member's join artifact including protocol metadata and a signed LeafNode."""

    version: MLSVersion = MLSVersion.MLS10
    cipher_suite: CipherSuite = CipherSuite(
        KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM
    )
    init_key: bytes = b""  # HPKE init key (distinct from leaf_node.encryption_key)
    leaf_node: Optional[LeafNode] = None
    signature: Signature = Signature(b"")

    def serialize(self) -> bytes:
        """
        Encode as:
          uint16(version) || uint16(cipher_suite) || opaque(init_key) ||
          uint32(len(leaf_node)) || leaf_node || raw signature bytes.
        """
        if self.leaf_node is None:
            raise ValueError("leaf_node must be set for serialization")
        ln_bytes = self.leaf_node.serialize()
        out = struct.pack("!H", int(self.version))  # uint16 ProtocolVersion
        out += self.cipher_suite.serialize()  # uint16 suite_id
        out += serialize_bytes(self.init_key)
        out += struct.pack("!I", len(ln_bytes))
        out += ln_bytes
        out += self.signature.serialize()
        return out

    def tbs_serialize(self) -> bytes:
        """Encode KeyPackageTBS for signing."""
        if self.leaf_node is None:
            raise ValueError("leaf_node must be set for serialization")
        ln_bytes = self.leaf_node.serialize()
        out = struct.pack("!H", int(self.version))
        out += self.cipher_suite.serialize()
        out += serialize_bytes(self.init_key)
        out += struct.pack("!I", len(ln_bytes))
        out += ln_bytes
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyPackage":
        """
        Parse KeyPackage from bytes.
        Primary format: uint16(version) || uint16(suite_id) || opaque(init_key) || ...
        Legacy fallback: uint32(len(leaf_node)) || leaf_node || signature
        """
        if len(data) >= 4:
            # Try legacy format first: starts with uint32 length of leaf_node
            try:
                (len_ln_legacy,) = struct.unpack("!I", data[:4])
                if 4 + len_ln_legacy <= len(data):
                    ln_bytes_legacy = data[4 : 4 + len_ln_legacy]
                    sig_bytes_legacy = data[4 + len_ln_legacy :]
                    leaf_node_legacy = LeafNode.deserialize(ln_bytes_legacy)
                    signature_legacy = Signature.deserialize(sig_bytes_legacy)
                    return cls(
                        version=MLSVersion.MLS10,
                        cipher_suite=CipherSuite(
                            KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM
                        ),
                        init_key=b"",
                        leaf_node=leaf_node_legacy,
                        signature=signature_legacy,
                    )
            except Exception:
                pass
        # New encoding: uint16(version) || uint16(suite_id) || opaque(init_key) || ...
        (ver_val,) = struct.unpack("!H", data[:2])
        version = MLSVersion(ver_val)
        cipher_suite = CipherSuite.deserialize(data[2:4])
        rest = data[4:]
        init_key, rest = deserialize_bytes(rest)
        (len_ln,) = struct.unpack("!I", rest[:4])
        rest = rest[4:]
        ln_bytes = rest[:len_ln]
        sig_bytes = rest[len_ln:]
        leaf_node = LeafNode.deserialize(ln_bytes)
        signature = Signature.deserialize(sig_bytes)
        return cls(
            version=version,
            cipher_suite=cipher_suite,
            init_key=init_key,
            leaf_node=leaf_node,
            signature=signature,
        )

    def verify(self, crypto_provider) -> None:
        """Verify the KeyPackage signature and credential consistency.

        Ensures that the credential public key matches the leaf's signature_key,
        then verifies the signature over the serialized LeafNode with domain separation.
        Also enforces version and cipher suite compatibility and that init_key
        (if present) differs from the leaf's encryption_key.
        """
        if self.leaf_node is None:
            raise InvalidSignatureError("missing leaf_node in KeyPackage")
        # Ensure credential public key matches the leaf signature key (if credential present)
        cred = self.leaf_node.credential
        if cred is not None and cred.public_key != self.leaf_node.signature_key:
            raise InvalidSignatureError("credential public key does not match leaf signature key")
        # Enforce version
        if self.version != MLSVersion.MLS10:
            raise InvalidSignatureError("unsupported MLS version in KeyPackage")
        # Enforce cipher suite compatibility with the active provider
        cs = crypto_provider.active_ciphersuite
        if not (
            self.cipher_suite.kem == cs.kem
            and self.cipher_suite.kdf == cs.kdf
            and self.cipher_suite.aead == cs.aead
        ):
            raise InvalidSignatureError("KeyPackage cipher suite does not match active provider")
        # Enforce init_key != encryption_key when init_key present
        if self.init_key and self.leaf_node and self.init_key == self.leaf_node.encryption_key:
            raise InvalidSignatureError("init_key must differ from leaf_node.encryption_key")
        crypto_provider.verify_with_label(
            self.leaf_node.signature_key,
            b"KeyPackageTBS",
            self.leaf_node.serialize(),
            self.signature.value,
        )

"""LeafNode and KeyPackage structures with basic (de)serialization and verification."""
from dataclasses import dataclass
from enum import IntEnum
import struct

from .data_structures import Credential, Signature, serialize_bytes, deserialize_bytes, MLSVersion, CipherSuite
from ..crypto.ciphersuites import KEM, KDF, AEAD
from ..mls.exceptions import InvalidSignatureError
from ..extensions.extensions import Extension, serialize_extensions, deserialize_extensions, make_capabilities_ext
class LeafNodeSource(IntEnum):
    """Origin of the LeafNode per RFC §7.2 (simplified)."""
    KEY_PACKAGE = 1
    UPDATE = 2



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
    credential: Credential | None
    capabilities: bytes
    parent_hash: bytes = b""
    # RFC fields
    leaf_node_source: LeafNodeSource = LeafNodeSource.KEY_PACKAGE
    extensions: list[Extension] = None  # type: ignore[assignment]

    def serialize(self) -> bytes:
        """Encode fields; keep legacy ordering and append RFC source/extensions."""
        if self.extensions is None:
            exts: list[Extension] = []
        else:
            exts = self.extensions
        # If legacy capabilities provided, also mirror it as an extension for RFC-compat
        if self.capabilities:
            try:
                cap_ext = make_capabilities_ext(self.capabilities)
                # Avoid duplicate CAPABILITIES extension if already present
                if not any(e.ext_type == cap_ext.ext_type for e in exts):
                    exts = exts + [cap_ext]
            except Exception:
                pass
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        cred_bytes = self.credential.serialize() if self.credential is not None else b""
        data += serialize_bytes(cred_bytes)
        data += serialize_bytes(self.capabilities)
        data += serialize_bytes(self.parent_hash)
        # Append RFC additions
        data += struct.pack("!B", int(self.leaf_node_source))
        data += serialize_bytes(serialize_extensions(exts))
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
        credential = Credential.deserialize(cred_bytes) if cred_bytes else None
        caps, rest = deserialize_bytes(rest)
        parent_hash = b""
        try:
            parent_hash, rest2 = deserialize_bytes(rest)
            # If extra trailing bytes exist, ignore safely
            _ = rest2
        except Exception:
            parent_hash = b""
            rest2 = b""
        # Defaults
        source = LeafNodeSource.KEY_PACKAGE
        extensions: list[Extension] = []
        # Parse optional source and extensions if present
        try:
            if rest2 is not None and len(rest2) >= 1:
                source_val, = struct.unpack("!B", rest2[:1])
                source = LeafNodeSource(source_val)
                ext_blob, _ = deserialize_bytes(rest2[1:]) if len(rest2) > 1 else (b"", b"")
                if ext_blob:
                    extensions = deserialize_extensions(ext_blob)
        except Exception:
            extensions = []
        return cls(enc_key, sig_key, credential, caps, parent_hash, source, extensions)


@dataclass(frozen=True)
class KeyPackage:
    """A member's join artifact including protocol metadata and a signed LeafNode."""
    version: MLSVersion = MLSVersion.MLS10
    cipher_suite: CipherSuite = CipherSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM)
    init_key: bytes = b""  # HPKE init key (distinct from leaf_node.encryption_key)
    leaf_node: LeafNode | None = None
    signature: Signature = Signature(b"")

    def serialize(self) -> bytes:
        """
        Encode as:
          opaque16(version) || CipherSuite(6 bytes) || opaque16(init_key) ||
          uint32(len(leaf_node)) || leaf_node || raw signature bytes.
        """
        if self.leaf_node is None:
            raise ValueError("leaf_node must be set for serialization")
        ln_bytes = self.leaf_node.serialize()
        out = serialize_bytes(self.version.value.encode("utf-8"))
        out += self.cipher_suite.serialize()
        out += serialize_bytes(self.init_key)
        out += struct.pack("!I", len(ln_bytes))
        out += ln_bytes
        out += self.signature.serialize()
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyPackage":
        """
        Parse KeyPackage from bytes.
        Backward-compatibility: If the blob starts with uint32(len(leaf_node)),
        parse legacy encoding without version/cipher_suite/init_key and set defaults.
        """
        if len(data) >= 4:
            try:
                len_ln_legacy, = struct.unpack("!I", data[:4])
                if 4 + len_ln_legacy <= len(data):
                    ln_bytes_legacy = data[4:4+len_ln_legacy]
                    sig_bytes_legacy = data[4+len_ln_legacy:]
                    leaf_node_legacy = LeafNode.deserialize(ln_bytes_legacy)
                    signature_legacy = Signature.deserialize(sig_bytes_legacy)
                    return cls(
                        version=MLSVersion.MLS10,
                        cipher_suite=CipherSuite(KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM),
                        init_key=b"",
                        leaf_node=leaf_node_legacy,
                        signature=signature_legacy,
                    )
            except Exception:
                pass
        # New encoding
        ver_bytes, rest = deserialize_bytes(data)
        version = MLSVersion(ver_bytes.decode("utf-8"))
        cipher_suite = CipherSuite.deserialize(rest[:6])
        rest = rest[6:]
        init_key, rest = deserialize_bytes(rest)
        len_ln, = struct.unpack("!I", rest[:4])
        rest = rest[4:]
        ln_bytes = rest[:len_ln]
        sig_bytes = rest[len_ln:]
        leaf_node = LeafNode.deserialize(ln_bytes)
        signature = Signature.deserialize(sig_bytes)
        return cls(version=version, cipher_suite=cipher_suite, init_key=init_key, leaf_node=leaf_node, signature=signature)

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
        if not (self.cipher_suite.kem == cs.kem and self.cipher_suite.kdf == cs.kdf and self.cipher_suite.aead == cs.aead):
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

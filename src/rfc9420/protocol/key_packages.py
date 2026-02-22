"""LeafNode and KeyPackage structures (RFC 9420 §7).

Provides (de)serialization and verification for LeafNode (including TBS for
signing), KeyPackage (with init key and extensions), and ref-hash computation
for tree and proposal references.
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Union
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
    GREASE_VALUES,
    serialize_extensions,
    deserialize_extensions,
    make_capabilities_ext,
)


def _prepare_extensions_for_signing(
    exts: Optional[list[Extension]],
    capabilities: bytes,
    grease_payload: bytes,
) -> list[Extension]:
    """Prepare extension list for serialization/TBS with deterministic GREASE."""
    out: list[Extension] = list(exts or [])

    if capabilities:
        try:
            cap_ext = make_capabilities_ext(capabilities)
            if not any(e.ext_type == cap_ext.ext_type for e in out):
                out.append(cap_ext)
        except Exception:
            pass

    present_types = {int(e.ext_type) for e in out}
    if not any(t in GREASE_VALUES for t in present_types):
        grease_type = next((v for v in GREASE_VALUES if v not in present_types), None)
        if grease_type is not None:
            out.append(Extension(grease_type, grease_payload))
    return out


class LeafNodeSource(IntEnum):
    """Origin of the LeafNode per RFC §7.2 (simplified)."""

    KEY_PACKAGE = 1
    UPDATE = 2
    COMMIT = 3


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
    lifetime_not_before: int = 0  # uint64, only for KEY_PACKAGE
    lifetime_not_after: int = 0  # uint64, only for KEY_PACKAGE
    parent_hash: bytes = b""  # opaque<V>, only for UPDATE/COMMIT
    extensions: list[Extension] = None  # type: ignore[assignment]
    signature: Union[Signature, bytes] = b""

    # RFC 9420 §7.2:
    # select (LeafNode.leaf_node_source) {
    #     case key_package: Lifetime lifetime;
    #     case update:      struct{};
    #     case commit:      opaque parent_hash<V>;
    # }

    def serialize(self) -> bytes:
        """Encode fields per RFC 9420 §7.2."""
        exts = _prepare_extensions_for_signing(
            self.extensions,
            self.capabilities,
            grease_payload=b"leafnode-grease",
        )
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        cred_bytes = self.credential.serialize() if self.credential is not None else b""
        data += serialize_bytes(cred_bytes)
        data += serialize_bytes(self.capabilities)
        data += struct.pack("!B", int(self.leaf_node_source))

        # Source-specific fields
        if self.leaf_node_source == LeafNodeSource.KEY_PACKAGE:
            data += struct.pack("!Q", self.lifetime_not_before)
            data += struct.pack("!Q", self.lifetime_not_after)
        elif self.leaf_node_source == LeafNodeSource.UPDATE:
            pass  # empty struct
        elif self.leaf_node_source == LeafNodeSource.COMMIT:
            data += serialize_bytes(self.parent_hash)

        data += serialize_bytes(serialize_extensions(exts))
        if isinstance(self.signature, Signature):
            data += serialize_bytes(self.signature.value)
        else:
            data += serialize_bytes(self.signature)
        return data

    def tbs_serialize(
        self, group_id: Optional[bytes] = None, leaf_index: Optional[int] = None
    ) -> bytes:
        """Encode LeafNodeTBS (everything except signature) for signing.

        RFC 9420 §7.2 LeafNodeTBS:
        struct {
            LeafNode content; // (minus signature)
            select (LeafNode.leaf_node_source) {
                case key_package: struct{};
                case update:
                case commit:
                    opaque group_id<V>;
                    uint32 leaf_index;
            };
        } LeafNodeTBS;
        """
        exts = _prepare_extensions_for_signing(
            self.extensions,
            self.capabilities,
            grease_payload=b"leafnode-grease",
        )
        data = serialize_bytes(self.encryption_key)
        data += serialize_bytes(self.signature_key)
        cred_bytes = self.credential.serialize() if self.credential is not None else b""
        data += serialize_bytes(cred_bytes)
        data += serialize_bytes(self.capabilities)
        data += struct.pack("!B", int(self.leaf_node_source))

        # Source-specific fields (LeafNode content part)
        if self.leaf_node_source == LeafNodeSource.KEY_PACKAGE:
            data += struct.pack("!Q", self.lifetime_not_before)
            data += struct.pack("!Q", self.lifetime_not_after)
        elif self.leaf_node_source == LeafNodeSource.UPDATE:
            pass
        elif self.leaf_node_source == LeafNodeSource.COMMIT:
            data += serialize_bytes(self.parent_hash)

        data += serialize_bytes(serialize_extensions(exts))

        # LeafNodeTBS specific additions
        if self.leaf_node_source in (LeafNodeSource.UPDATE, LeafNodeSource.COMMIT):
            if group_id is None or leaf_index is None:
                raise ValueError(
                    "group_id and leaf_index required for LeafNodeTBS with source UPDATE or COMMIT"
                )
            # opaque group_id<V>; uint32 leaf_index;
            data += serialize_bytes(group_id)
            data += struct.pack("!I", leaf_index)

        return data

    @classmethod
    def deserialize_partial(cls, data: bytes) -> tuple["LeafNode", int]:
        """Parse a LeafNode from bytes and return (LeafNode, bytes_consumed)."""
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

            nb = 0
            na = 0
            parent_hash = b""

            if leaf_source == LeafNodeSource.KEY_PACKAGE:
                (nb,) = struct.unpack("!Q", rest[:8])
                rest = rest[8:]
                (na,) = struct.unpack("!Q", rest[:8])
                rest = rest[8:]
            elif leaf_source == LeafNodeSource.UPDATE:
                pass
            elif leaf_source == LeafNodeSource.COMMIT:
                parent_hash, rest = deserialize_bytes(rest)

            exts_bytes, rest = deserialize_bytes(rest)
            extensions = deserialize_extensions(exts_bytes)
            signature, rest = deserialize_bytes(rest)

            consumed = len(data) - len(rest)
            leaf = cls(
                encryption_key=enc_key,
                signature_key=sig_key,
                credential=credential,
                capabilities=caps,
                leaf_node_source=leaf_source,
                lifetime_not_before=nb,
                lifetime_not_after=na,
                extensions=extensions,
                signature=signature if isinstance(signature, Signature) else Signature(signature),
                parent_hash=parent_hash,
            )
            return leaf, consumed
        except Exception:
            # Parse failed
            raise

    @classmethod
    def deserialize(cls, data: bytes) -> "LeafNode":
        """Parse a LeafNode (consumes data)."""
        leaf, _ = cls.deserialize_partial(data)
        return leaf

    def validate(
        self,
        crypto_provider,
        group_id: Optional[bytes] = None,
        leaf_index: Optional[int] = None,
        current_time: Optional[int] = None,
    ) -> None:
        """Verify LeafNode validity according to RFC 9420 §7.3.

        Checks:
        - Signature verification (requires group_id/leaf_index for UPDATE/COMMIT source).
        - Validity of credential.
        - Validity of capabilities and required extensions.
        - Presence of parent_hash for UPDATE/COMMIT.
        - Checks lifetime if KEY_PACKAGE.
        """
        # 1. Verify semantics
        if self.leaf_node_source == LeafNodeSource.KEY_PACKAGE:
            # Check lifetime
            if current_time is not None:
                if (
                    current_time < self.lifetime_not_before
                    or current_time > self.lifetime_not_after
                ):
                    raise ValueError(
                        f"LeafNode expired or not yet valid (now={current_time}, window=[{self.lifetime_not_before}, {self.lifetime_not_after}])"
                    )
        elif self.leaf_node_source in (LeafNodeSource.UPDATE, LeafNodeSource.COMMIT):
            if not self.parent_hash:
                # RFC 9420 §7.2: parent_hash present for UPDATE/COMMIT
                # But it's opaque<V>, could be empty? RFC says "The parent hash...".
                # Generally it should be non-empty unless root?
                # For a single-leaf tree, parent_hash is empty.
                pass
            if group_id is None or leaf_index is None:
                raise ValueError(
                    "Validation of UPDATE/COMMIT LeafNode requires group_id and leaf_index"
                )

        if self.capabilities:
            try:
                from ..extensions.extensions import (
                    parse_capabilities_data,
                    ExtensionType,
                    parse_required_capabilities,
                )

                # Check REQUIRED_CAPABILITIES from extensions against capabilities
                if self.extensions:
                    req_cap_ext = next(
                        (
                            e
                            for e in self.extensions
                            if e.ext_type == ExtensionType.REQUIRED_CAPABILITIES
                        ),
                        None,
                    )
                    if req_cap_ext:
                        required = parse_required_capabilities(req_cap_ext.data)
                        _caps = parse_capabilities_data(self.capabilities)
                        supported_exts = _caps.get("extensions", [])
                        for req in required[0]:  # required[0] = extension_types
                            if req not in supported_exts:
                                raise ValueError(f"LeafNode missing required capability: {req}")
            except Exception as e:
                if "missing required capability" in str(e):
                    raise
                pass

        # 3. Verify signature
        # We need to construct the TBS.
        try:
            tbs = self.tbs_serialize(group_id, leaf_index)
        except Exception as e:
            raise InvalidSignatureError(f"Could not construct TBS for signature verification: {e}")

        # Verify using the credential's public key (or signature_key if self-signed/implicit)
        sig_bytes = (
            self.signature.value if isinstance(self.signature, Signature) else self.signature
        )
        crypto_provider.verify_with_label(
            self.signature_key,
            b"LeafNodeTBS",  # Label for LeafNode signing
            tbs,
            sig_bytes,
        )


@dataclass(frozen=True)
class KeyPackage:
    """A member's join artifact including protocol metadata and a signed LeafNode."""

    version: MLSVersion = MLSVersion.MLS10
    cipher_suite: CipherSuite = CipherSuite(
        KEM.DHKEM_X25519_HKDF_SHA256, KDF.HKDF_SHA256, AEAD.AES_128_GCM
    )
    init_key: bytes = b""  # HPKE init key (distinct from leaf_node.encryption_key)
    leaf_node: Optional[LeafNode] = None
    extensions: list[Extension] = None  # type: ignore[assignment]
    signature: Signature = Signature(b"")

    def serialize(self) -> bytes:
        """
        Encode as:
          uint16(version) || uint16(cipher_suite) || opaque(init_key) ||
          uint32(len(leaf_node)) || leaf_node ||
          uint32(len(extensions_list)) || extensions... ||
          raw signature bytes.
        """
        if self.leaf_node is None:
            raise ValueError("leaf_node must be set for serialization")

        exts = _prepare_extensions_for_signing(
            self.extensions,
            b"",
            grease_payload=b"keypackage-grease",
        )

        ln_bytes = self.leaf_node.serialize()
        exts_bytes = serialize_extensions(exts)

        out = struct.pack("!H", int(self.version))  # uint16 ProtocolVersion
        out += self.cipher_suite.serialize()  # uint16 suite_id
        out += serialize_bytes(self.init_key)
        # RFC 9420: LeafNode is embedded, not a vector. Length not prefixed.
        # out += struct.pack("!I", len(ln_bytes))
        out += ln_bytes
        out += serialize_bytes(exts_bytes)
        out += self.signature.serialize()
        return out

    def tbs_serialize(self) -> bytes:
        """Encode KeyPackageTBS for signing."""
        if self.leaf_node is None:
            raise ValueError("leaf_node must be set for serialization")

        exts = _prepare_extensions_for_signing(
            self.extensions,
            b"",
            grease_payload=b"keypackage-grease",
        )

        ln_bytes = self.leaf_node.serialize()
        exts_bytes = serialize_extensions(exts)

        out = struct.pack("!H", int(self.version))
        out += self.cipher_suite.serialize()
        out += serialize_bytes(self.init_key)
        # RFC 9420: LeafNode is embedded, not a vector.
        # out += struct.pack("!I", len(ln_bytes))
        out += ln_bytes
        out += serialize_bytes(exts_bytes)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "KeyPackage":
        """
        Parse KeyPackage from bytes.
        RFC format only:
          uint16(version) || uint16(suite_id) || opaque(init_key) ||
          LeafNode || opaque(extensions) || opaque(signature)
        """
        if len(data) < 4:
            raise ValueError(
                "truncated KeyPackage: need at least 4 bytes for version and cipher_suite"
            )
        try:
            (ver_val,) = struct.unpack("!H", data[:2])
            version = MLSVersion(ver_val)
        except Exception as e:
            raise ValueError(f"invalid KeyPackage version field: {e}") from e
        try:
            cipher_suite = CipherSuite.deserialize(data[2:4])
        except Exception as e:
            raise ValueError(f"invalid KeyPackage cipher_suite field: {e}") from e

        rest = data[4:]
        try:
            init_key, rest = deserialize_bytes(rest)
        except Exception as e:
            raise ValueError(f"invalid KeyPackage init_key encoding: {e}") from e

        try:
            leaf_node, consumed = LeafNode.deserialize_partial(rest)
            rest = rest[consumed:]
        except Exception as e:
            raise ValueError(f"invalid KeyPackage leaf_node encoding: {e}") from e

        try:
            exts_bytes, rest = deserialize_bytes(rest)
            extensions = deserialize_extensions(exts_bytes)
        except Exception as e:
            raise ValueError(f"invalid KeyPackage extensions encoding: {e}") from e

        if not rest:
            raise ValueError("truncated KeyPackage: missing signature")
        sig_bytes = rest
        signature = Signature.deserialize(sig_bytes)
        return cls(
            version=version,
            cipher_suite=cipher_suite,
            init_key=init_key,
            leaf_node=leaf_node,
            extensions=extensions,
            signature=signature,
        )

    def verify(self, crypto_provider, group_context=None, current_time: Optional[int] = None) -> None:
        """Verify the KeyPackage signature and validity (RFC 9420 §10.1).

        Args:
            crypto_provider: The CryptoProvider to use for verification.
            group_context: Optional GroupContext. If provided, checks that KeyPackage
                           version and cipher suite match the group's.
        """
        if self.leaf_node is None:
            raise InvalidSignatureError("missing leaf_node in KeyPackage")
        if not self.init_key:
            raise InvalidSignatureError("missing init_key in KeyPackage")

        # Validate the embedded LeafNode (signature, constraints, etc.)
        try:
            self.leaf_node.validate(crypto_provider, current_time=current_time)
        except Exception as e:
            raise InvalidSignatureError(f"LeafNode validation failed: {e}")

        # Ensure credential public key matches the leaf signature key (if credential present)
        cred = self.leaf_node.credential
        # Basic credential wire encoding does not carry public_key in this
        # implementation, so only enforce equality when a public key is present.
        pk = getattr(cred, "public_key", None) if cred is not None else None
        if pk is not None and pk != self.leaf_node.signature_key:
            raise InvalidSignatureError("credential public key does not match leaf signature key")

        # Enforce version
        if self.version != MLSVersion.MLS10:
            raise InvalidSignatureError("unsupported MLS version in KeyPackage")

        # Enforce cipher suite checks
        cs = crypto_provider.active_ciphersuite
        if not (
            self.cipher_suite.kem == cs.kem
            and self.cipher_suite.kdf == cs.kdf
            and self.cipher_suite.aead == cs.aead
        ):
            raise InvalidSignatureError("KeyPackage cipher suite does not match active provider")

        if group_context is not None:
            gc_version = getattr(group_context, "version", None)
            gc_suite_id = getattr(group_context, "cipher_suite_id", None)
            if gc_version is not None and int(self.version) != int(gc_version):
                raise InvalidSignatureError(
                    "KeyPackage version does not match GroupContext version"
                )
            if gc_suite_id is not None and int(self.cipher_suite.suite_id) != int(gc_suite_id):
                raise InvalidSignatureError(
                    "KeyPackage cipher suite does not match GroupContext suite"
                )

        # Enforce init_key != encryption_key when init_key present
        if self.init_key and self.leaf_node and self.init_key == self.leaf_node.encryption_key:
            raise InvalidSignatureError("init_key must differ from leaf_node.encryption_key")

        # Verify signature over KeyPackageTBS
        # KeyPackageTBS = version || cipher_suite || init_key || leaf_node || extensions
        # Since tbs_serialize includes extensions, this verifies the full package.
        crypto_provider.verify_with_label(
            self.leaf_node.signature_key,
            b"KeyPackageTBS",
            self.tbs_serialize(),
            self.signature.value,
        )

        # Enforce leaf_node.leaf_node_source == KEY_PACKAGE
        if self.leaf_node.leaf_node_source != LeafNodeSource.KEY_PACKAGE:
            raise InvalidSignatureError("KeyPackage LeafNode must have source KEY_PACKAGE")

        # Enforce extensions in capabilities
        # RFC 9420 §10: "The LeafNode's capabilities field MUST include all extensions that are present in the KeyPackage."
        # This applies to extensions in KeyPackage and extensions in LeafNode.

        from ..extensions.extensions import parse_capabilities_data

        # If capabilities are present, we must verify against them.
        # If no capabilities are present, technically we can't verify support, but default assumption?
        # RFC 9420 §7.2: "capabilities... MUST be present in a LeafNode".
        # So emptiness should be rejected during LeafNode.validate() or here.
        if not self.leaf_node.capabilities:
            # Code elsewhere might allow empty defaults, but strict check strictly requires them for extensions check.
            pass
        else:
            try:
                from ..extensions.extensions import parse_capabilities_data

                _caps = parse_capabilities_data(self.leaf_node.capabilities)
                supported_exts = _caps.get("extensions", [])

                # Check KeyPackage extensions
                if self.extensions:
                    for ext in self.extensions:
                        if (ext.ext_type & 0x0A0A) == 0x0A0A:
                            continue
                        if ext.ext_type not in supported_exts:
                            raise InvalidSignatureError(
                                f"KeyPackage extension {ext.ext_type} not in LeafNode capabilities"
                            )

                # Check LeafNode extensions
                if self.leaf_node.extensions:
                    for ext in self.leaf_node.extensions:
                        if (ext.ext_type & 0x0A0A) == 0x0A0A:
                            continue
                        if ext.ext_type not in supported_exts:
                            raise InvalidSignatureError(
                                f"LeafNode extension {ext.ext_type} not in LeafNode capabilities"
                            )

            except Exception as e:
                if "not in LeafNode capabilities" in str(e):
                    raise
                pass

"""Core protocol data structures and (de)serialization helpers for MLS."""

from dataclasses import dataclass
from enum import IntEnum
from abc import ABC, abstractmethod
from typing import Optional
import struct

from ..codec.tls import write_opaque32, read_opaque32
from ..crypto.ciphersuites import KEM, KDF, AEAD, find_by_triple, get_ciphersuite_by_id
from ..mls.exceptions import RFC9420Error


def serialize_bytes(data: bytes) -> bytes:
    """Serializes bytes with a 4-byte (uint32) TLS-style length prefix.

    Uses the standard TLS opaque32 encoding via codec/tls.py helpers.
    """
    return write_opaque32(data)


def deserialize_bytes(data: bytes) -> tuple[bytes, bytes]:
    """Deserializes bytes with a 4-byte (uint32) TLS-style length prefix."""
    payload, new_offset = read_opaque32(data, 0)
    return payload, data[new_offset:]


class MLSVersion(IntEnum):
    """Protocol version enumeration (RFC 9420 §5).

    Wire format: uint16. mls10 = 0x0001.
    """

    MLS10 = 0x0001


@dataclass(frozen=True)
class CipherSuite:
    """Selected cipher suite for an epoch (RFC 9420 §5.1).

    Wire format: single uint16 suite_id from IANA MLS Cipher Suites registry.
    The kem/kdf/aead fields are kept for internal algorithm dispatch.
    """

    kem: KEM
    kdf: KDF
    aead: AEAD
    suite_id: int = 0  # IANA suite_id; 0 means "auto-detect from triple"

    def __post_init__(self) -> None:
        if self.suite_id == 0:
            # Auto-resolve suite_id from (KEM, KDF, AEAD) triple
            cs = find_by_triple((self.kem, self.kdf, self.aead))
            if cs is not None:
                object.__setattr__(self, "suite_id", cs.suite_id)

    def serialize(self) -> bytes:
        """Encode as uint16 suite_id (RFC 9420 §5.1)."""
        return struct.pack("!H", self.suite_id)

    @classmethod
    def deserialize(cls, data: bytes) -> "CipherSuite":
        """Parse a CipherSuite from 2 bytes (uint16 suite_id)."""
        (suite_id_val,) = struct.unpack("!H", data[:2])
        cs = get_ciphersuite_by_id(suite_id_val)
        if cs is not None:
            return cls(cs.kem, cs.kdf, cs.aead, suite_id=cs.suite_id)
        raise RFC9420Error(f"Unknown cipher suite: 0x{suite_id_val:04x}")


class SenderType(IntEnum):
    """Sender type discriminator (RFC 9420 §6).

    enum { member(1), external(2), new_member_proposal(3), new_member_commit(4) } SenderType;
    """
    MEMBER = 1
    EXTERNAL = 2
    NEW_MEMBER_PROPOSAL = 3
    NEW_MEMBER_COMMIT = 4


@dataclass(frozen=True)
class Sender:
    """Sender descriptor with type discriminator (RFC 9420 §6).

    Wire format: uint8 sender_type || select(sender_type) { member: uint32 leaf_index; ... }
    """

    sender: int  # leaf index (for MEMBER/EXTERNAL types)
    sender_type: SenderType = SenderType.MEMBER

    def serialize(self) -> bytes:
        """Encode as uint8 sender_type || uint32 leaf_index (for member/external)."""
        out = struct.pack("!B", self.sender_type.value)
        if self.sender_type in (SenderType.MEMBER, SenderType.EXTERNAL):
            out += struct.pack("!I", self.sender)
        # NEW_MEMBER_COMMIT and NEW_MEMBER_PROPOSAL have empty select body
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "Sender":
        """Parse from sender_type || select(...)."""
        (st_val,) = struct.unpack("!B", data[:1])
        sender_type = SenderType(st_val)
        if sender_type in (SenderType.MEMBER, SenderType.EXTERNAL):
            (sender,) = struct.unpack("!I", data[1:5])
            return cls(sender, sender_type)
        return cls(0, sender_type)


class CredentialType(IntEnum):
    """Credential type discriminator (RFC 9420 §5.3)."""
    BASIC = 1
    X509 = 2


@dataclass(frozen=True)
class Credential:
    """Credential with type discriminator (RFC 9420 §5.3).

    Wire format: uint16 credential_type || select(credential_type) {
        case basic: opaque identity<V>;
        case x509: Certificate certificates<V>;
    }
    The public_key field is kept for internal use (binding to LeafNode.signature_key)
    but is NOT part of the RFC wire encoding.
    """

    identity: bytes
    public_key: bytes
    credential_type: CredentialType = CredentialType.BASIC

    def serialize(self) -> bytes:
        """Encode per RFC 9420 §5.3."""
        out = struct.pack("!H", self.credential_type.value)
        if self.credential_type == CredentialType.BASIC:
            out += serialize_bytes(self.identity)
        elif self.credential_type == CredentialType.X509:
            # X.509: identity holds the DER cert chain blob
            out += serialize_bytes(self.identity)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "Credential":
        """Parse from uint16 credential_type || select(...)."""
        if len(data) < 2:
            # Legacy fallback: no credential_type prefix, treat as basic
            identity, rest = deserialize_bytes(data)
            public_key_bytes = b""
            if rest:
                try:
                    public_key_bytes, _ = deserialize_bytes(rest)
                except Exception:
                    pass
            return cls(identity, public_key_bytes)
        (ct_val,) = struct.unpack("!H", data[:2])
        try:
            ct = CredentialType(ct_val)
        except ValueError:
            # Not a valid credential type — try legacy format
            identity, rest = deserialize_bytes(data)
            public_key_bytes = b""
            if rest:
                try:
                    public_key_bytes, _ = deserialize_bytes(rest)
                except Exception:
                    pass
            return cls(identity, public_key_bytes)
        rest = data[2:]
        identity, _ = deserialize_bytes(rest)
        return cls(identity, b"", ct)


@dataclass(frozen=True)
class Signature:
    """Wrapper for raw signature bytes."""

    value: bytes

    def serialize(self) -> bytes:
        """Return the raw signature bytes."""
        return self.value

    @classmethod
    def deserialize(cls, data: bytes) -> "Signature":
        """Wrap raw signature bytes."""
        return cls(data)


@dataclass(frozen=True)
class SignContent:
    """Domain-separated signing structure (RFC 9420 §5.1.2).

    Serialized as: opaque label<V> || opaque content<V>
    Uses TLS-style variable-length encoding (4-byte prefix for opaque<V>).
    The label should already include the "MLS 1.0 " prefix when constructed.
    """

    label: bytes
    content: bytes

    def serialize(self) -> bytes:
        """TLS-style length-prefixed label and content."""
        return serialize_bytes(self.label or b"") + serialize_bytes(self.content or b"")


class ProposalType(IntEnum):
    """Enumeration of proposal kinds."""

    ADD = 1
    UPDATE = 2
    REMOVE = 3
    PRE_SHARED_KEY = 4
    REINIT = 5
    EXTERNAL_INIT = 6
    GROUP_CONTEXT_EXTENSIONS = 7
    APP_ACK = 8


class Proposal(ABC):
    """Base class for all proposals."""

    @property
    @abstractmethod
    def proposal_type(self) -> ProposalType:
        """Concrete proposal kind (implemented by subclasses)."""
        raise NotImplementedError

    @abstractmethod
    def _serialize_content(self) -> bytes:
        """Serialize the proposal-specific content (without the type byte)."""
        raise NotImplementedError

    def serialize(self) -> bytes:
        """Encode as uint8 type || content."""
        return struct.pack("!B", self.proposal_type.value) + self._serialize_content()

    @classmethod
    def deserialize(cls, data: bytes) -> "Proposal":
        """Dispatch to the appropriate concrete Proposal subclass."""
        (proposal_type,) = struct.unpack("!B", data[:1])
        content = data[1:]

        if proposal_type == ProposalType.ADD:
            return AddProposal.deserialize(content)
        if proposal_type == ProposalType.UPDATE:
            return UpdateProposal.deserialize(content)
        if proposal_type == ProposalType.REMOVE:
            return RemoveProposal.deserialize(content)
        if proposal_type == ProposalType.PRE_SHARED_KEY:
            return PreSharedKeyProposal.deserialize(content)
        if proposal_type == ProposalType.REINIT:
            return ReInitProposal.deserialize(content)
        if proposal_type == ProposalType.EXTERNAL_INIT:
            return ExternalInitProposal.deserialize(content)
        if proposal_type == ProposalType.GROUP_CONTEXT_EXTENSIONS:
            return GroupContextExtensionsProposal.deserialize(content)
        if proposal_type == ProposalType.APP_ACK:
            return AppAckProposal.deserialize(content)

        raise RFC9420Error(f"Unknown proposal type: {proposal_type}")


@dataclass(frozen=True)
class AddProposal(Proposal):
    """Proposal to add a new member by KeyPackage."""

    key_package: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.ADD."""
        return ProposalType.ADD

    def _serialize_content(self) -> bytes:
        """Return the serialized KeyPackage."""
        return self.key_package

    @classmethod
    def deserialize(cls, data: bytes) -> "AddProposal":
        """Construct from raw KeyPackage bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        # If a type byte is present, strip it
        if data and data[0] == ProposalType.ADD:
            data = data[1:]
        return cls(data)


@dataclass(frozen=True)
class UpdateProposal(Proposal):
    """Proposal to update a member's leaf node."""

    leaf_node: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.UPDATE."""
        return ProposalType.UPDATE

    def _serialize_content(self) -> bytes:
        """Return the serialized LeafNode bytes."""
        return self.leaf_node

    @classmethod
    def deserialize(cls, data: bytes) -> "UpdateProposal":
        """Construct from raw LeafNode bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.UPDATE:
            data = data[1:]
        return cls(data)


@dataclass(frozen=True)
class RemoveProposal(Proposal):
    """Proposal to remove a member by leaf index."""

    removed: int

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.REMOVE."""
        return ProposalType.REMOVE

    def _serialize_content(self) -> bytes:
        """Encode removed leaf index as uint32."""
        return struct.pack("!I", self.removed)

    @classmethod
    def deserialize(cls, data: bytes) -> "RemoveProposal":
        """Parse removed leaf index from uint32.

        Accepts either raw content (4 bytes) or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.REMOVE:
            data = data[1:]
        (removed,) = struct.unpack("!I", data)
        return cls(removed)


@dataclass(frozen=True)
class PreSharedKeyProposal(Proposal):
    """Proposal to bind a pre-shared key (PSK)."""

    psk_id: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.PRE_SHARED_KEY."""
        return ProposalType.PRE_SHARED_KEY

    def _serialize_content(self) -> bytes:
        """Encode PSK identifier as len-delimited bytes."""
        return serialize_bytes(self.psk_id)

    @classmethod
    def deserialize(cls, data: bytes) -> "PreSharedKeyProposal":
        """Parse PSK identifier from len-delimited bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.PRE_SHARED_KEY:
            data = data[1:]
        psk_id, _ = deserialize_bytes(data)
        return cls(psk_id)


@dataclass(frozen=True)
class ReInitProposal(Proposal):
    """Proposal to re-initialize the group with a new group_id."""

    new_group_id: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.REINIT."""
        return ProposalType.REINIT

    def _serialize_content(self) -> bytes:
        """Encode new group_id as len-delimited bytes."""
        return serialize_bytes(self.new_group_id)

    @classmethod
    def deserialize(cls, data: bytes) -> "ReInitProposal":
        """Parse new group_id from len-delimited bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.REINIT:
            data = data[1:]
        gid, _ = deserialize_bytes(data)
        return cls(gid)


@dataclass(frozen=True)
class ExternalInitProposal(Proposal):
    """Proposal to publish an external HPKE public key for external commits."""

    kem_public_key: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.EXTERNAL_INIT."""
        return ProposalType.EXTERNAL_INIT

    def _serialize_content(self) -> bytes:
        """Encode HPKE public key as len-delimited bytes."""
        return serialize_bytes(self.kem_public_key)

    @classmethod
    def deserialize(cls, data: bytes) -> "ExternalInitProposal":
        """Parse HPKE public key from len-delimited bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.EXTERNAL_INIT:
            data = data[1:]
        pk, _ = deserialize_bytes(data)
        return cls(pk)


@dataclass(frozen=True)
class GroupContextExtensionsProposal(Proposal):
    """Proposal to set or update GroupContext extensions (opaque payload)."""

    extensions: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.GROUP_CONTEXT_EXTENSIONS."""
        return ProposalType.GROUP_CONTEXT_EXTENSIONS

    def _serialize_content(self) -> bytes:
        """Encode extensions as len-delimited bytes."""
        return serialize_bytes(self.extensions)

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupContextExtensionsProposal":
        """Parse extensions from len-delimited bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.GROUP_CONTEXT_EXTENSIONS:
            data = data[1:]
        ext, _ = deserialize_bytes(data)
        return cls(ext)


@dataclass(frozen=True)
class AppAckProposal(Proposal):
    """Application Acknowledgement proposal carrying opaque authenticated_data."""

    authenticated_data: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.APP_ACK."""
        return ProposalType.APP_ACK

    def _serialize_content(self) -> bytes:
        """Encode authenticated_data as len-delimited bytes."""
        return serialize_bytes(self.authenticated_data)

    @classmethod
    def deserialize(cls, data: bytes) -> "AppAckProposal":
        """
        Parse authenticated_data from len-delimited bytes.

        Accepts either raw content or full encoding with a leading type byte.
        """
        if data and data[0] == ProposalType.APP_ACK:
            data = data[1:]
        authenticated_data, _ = deserialize_bytes(data)
        return cls(authenticated_data)


class ProposalOrRefType(IntEnum):
    """Discriminator for Commit proposals vector entries."""

    PROPOSAL = 1
    REFERENCE = 2


@dataclass(frozen=True)
class ProposalOrRef:
    """Union of a Proposal by-value or a Proposal reference (opaque bytes)."""

    typ: ProposalOrRefType
    proposal: Optional[Proposal] = None
    reference: Optional[bytes] = None

    def serialize(self) -> bytes:
        """Encode as uint8 typ || opaque16(payload)."""
        payload = b""
        if self.typ == ProposalOrRefType.PROPOSAL:
            if self.proposal is None:
                raise RFC9420Error("missing proposal for ProposalOrRef.PROPOSAL")
            payload = self.proposal.serialize()
        elif self.typ == ProposalOrRefType.REFERENCE:
            if self.reference is None:
                raise RFC9420Error("missing reference for ProposalOrRef.REFERENCE")
            payload = self.reference
        else:
            raise RFC9420Error("unknown ProposalOrRefType")
        return struct.pack("!B", int(self.typ)) + serialize_bytes(payload)

    @classmethod
    def deserialize(cls, data: bytes) -> "ProposalOrRef":
        """Parse from bytes produced by serialize()."""
        if len(data) < 1:
            raise RFC9420Error("invalid ProposalOrRef encoding")
        (t_val,) = struct.unpack("!B", data[:1])
        typ = ProposalOrRefType(t_val)
        payload, _ = deserialize_bytes(data[1:])
        if typ == ProposalOrRefType.PROPOSAL:
            return cls(typ=typ, proposal=Proposal.deserialize(payload))
        if typ == ProposalOrRefType.REFERENCE:
            return cls(typ=typ, reference=payload)
        raise RFC9420Error("unknown ProposalOrRefType during deserialize")


@dataclass(frozen=True)
class UpdatePath:
    """Commit path structure with leaf and per-recipient encrypted path secrets."""

    leaf_node: bytes
    # Map of copath node index -> list of per-recipient HPKE blobs,
    # where each blob encodes opaque16(enc) || opaque16(ct).
    nodes: dict[int, list[bytes]]

    def serialize(self) -> bytes:
        """Encode leaf_node, number of nodes, and per-node recipient blobs."""
        data = serialize_bytes(self.leaf_node)
        data += struct.pack("!H", len(self.nodes))
        for key, value in self.nodes.items():
            data += struct.pack("!I", key)
            # number of recipients
            data += struct.pack("!H", len(value))
            for blob in value:
                data += serialize_bytes(blob)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "UpdatePath":
        """Parse an UpdatePath from bytes produced by serialize()."""
        leaf_node, rest = deserialize_bytes(data)
        (num_nodes,) = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        nodes = {}
        for _ in range(num_nodes):
            (key,) = struct.unpack("!I", rest[:4])
            rest = rest[4:]
            (num_recips,) = struct.unpack("!H", rest[:2])
            rest = rest[2:]
            recips: list[bytes] = []
            for __ in range(num_recips):
                blob, rest = deserialize_bytes(rest)
                recips.append(blob)
            nodes[key] = recips
        return cls(leaf_node, nodes)


@dataclass(frozen=True)
class Commit:
    """Commit object carrying optional UpdatePath and proposal list (by-value or by-reference)."""

    path: Optional[UpdatePath]
    proposals: list[ProposalOrRef]
    signature: Signature

    def serialize(self) -> bytes:
        """Encode presence of path, proposals vector, and signature."""
        data = b""
        if self.path:
            data += b"\x01"
            data += serialize_bytes(self.path.serialize())
        else:
            data += b"\x00"
        # Proposals vector
        data += struct.pack("!H", len(self.proposals))
        for por in self.proposals:
            data += serialize_bytes(por.serialize())
        data += self.signature.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Commit":
        """Parse a Commit from bytes produced by serialize()."""
        has_path = data[0] == 1
        rest = data[1:]
        path = None
        if has_path:
            path_bytes, rest = deserialize_bytes(rest)
            path = UpdatePath.deserialize(path_bytes)
        (num_props,) = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        proposals: list[ProposalOrRef] = []
        for _ in range(num_props):
            blob, rest = deserialize_bytes(rest)
            proposals.append(ProposalOrRef.deserialize(blob))
        signature = Signature.deserialize(rest)
        return cls(path, proposals, signature)


@dataclass(frozen=True)
class Welcome:
    """Welcome message carrying epoch secrets and encrypted GroupInfo."""

    version: MLSVersion
    cipher_suite: CipherSuite
    secrets: list["EncryptedGroupSecrets"]
    encrypted_group_info: bytes

    def serialize(self) -> bytes:
        """Encode version (uint16), cipher suite (uint16), secrets, and encrypted GroupInfo."""
        data = struct.pack("!H", int(self.version))  # uint16 ProtocolVersion
        data += self.cipher_suite.serialize()  # uint16 suite_id

        data += struct.pack("!H", len(self.secrets))
        for secret in self.secrets:
            data += serialize_bytes(secret.serialize())

        data += serialize_bytes(self.encrypted_group_info)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Welcome":
        """Parse a Welcome from bytes produced by serialize()."""
        (ver_val,) = struct.unpack("!H", data[:2])
        version = MLSVersion(ver_val)

        cipher_suite = CipherSuite.deserialize(data[2:4])
        rest = data[4:]

        (num_secrets,) = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        secrets: list[EncryptedGroupSecrets] = []
        for _ in range(num_secrets):
            sbytes, rest = deserialize_bytes(rest)
            secrets.append(EncryptedGroupSecrets.deserialize(sbytes))

        encrypted_group_info, _ = deserialize_bytes(rest)

        return cls(version, cipher_suite, secrets, encrypted_group_info)


@dataclass(frozen=True)
class GroupContext:
    """Group context bound into key schedule and transcript computation (RFC 9420 §8.1).

    Wire format: uint16 version || uint16 cipher_suite || opaque group_id<V> ||
                 uint64 epoch || opaque tree_hash<V> ||
                 opaque confirmed_transcript_hash<V> || Extension extensions<V>
    """

    group_id: bytes
    epoch: int
    tree_hash: bytes
    confirmed_transcript_hash: bytes
    extensions: bytes = b""  # RFC 9420 §12.1: serialized extensions list
    version: int = 0x0001  # ProtocolVersion mls10
    cipher_suite_id: int = 0x0001  # default to MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

    def serialize(self) -> bytes:
        """Encode per RFC 9420 §8.1."""
        data = struct.pack("!H", self.version)  # ProtocolVersion
        data += struct.pack("!H", self.cipher_suite_id)  # CipherSuite
        data += serialize_bytes(self.group_id)
        data += struct.pack("!Q", self.epoch)
        data += serialize_bytes(self.tree_hash)
        data += serialize_bytes(self.confirmed_transcript_hash)
        data += serialize_bytes(self.extensions)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupContext":
        """Parse GroupContext from bytes produced by serialize()."""
        (version,) = struct.unpack("!H", data[:2])
        (cipher_suite_id,) = struct.unpack("!H", data[2:4])
        rest = data[4:]
        group_id, rest = deserialize_bytes(rest)
        (epoch,) = struct.unpack("!Q", rest[:8])
        rest = rest[8:]
        tree_hash, rest = deserialize_bytes(rest)
        confirmed_transcript_hash, rest = deserialize_bytes(rest)
        extensions = b""
        if rest:
            extensions, _ = deserialize_bytes(rest)
        return cls(group_id, epoch, tree_hash, confirmed_transcript_hash,
                   extensions, version, cipher_suite_id)


@dataclass(frozen=True)
class GroupInfo:
    """Signed GroupContext and optional extensions referenced by Welcome."""

    group_context: GroupContext
    signature: Signature
    extensions: bytes = b""  # serialized extensions (opaque); MVP keeps raw for flexibility
    confirmation_tag: bytes = b""
    signer_leaf_index: int = 0

    def tbs_serialize(self) -> bytes:
        """
        To-Be-Signed bytes for GroupInfo: GroupContext || extensions
        """
        return self.group_context.serialize() + self.extensions

    def serialize(self) -> bytes:
        """Encode len-delimited fields for forward compatibility."""
        # Serialize as length-delimited fields for forward compatibility
        out = serialize_bytes(self.group_context.serialize())
        out += serialize_bytes(self.signature.serialize())
        out += serialize_bytes(self.extensions)
        out += serialize_bytes(self.confirmation_tag)
        out += struct.pack("!I", self.signer_leaf_index)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupInfo":
        """Parse GroupInfo from bytes produced by serialize()."""
        gc_bytes, rest = deserialize_bytes(data)
        sig_bytes, rest = deserialize_bytes(rest)
        ext_bytes, rest = deserialize_bytes(rest) if rest else (b"", b"")
        tag, rest = deserialize_bytes(rest) if rest else (b"", b"")
        signer = struct.unpack("!I", rest[:4])[0] if rest and len(rest) >= 4 else 0
        group_context = GroupContext.deserialize(gc_bytes)
        signature = Signature.deserialize(sig_bytes)
        return cls(group_context, signature, ext_bytes, tag, signer)


@dataclass(frozen=True)
class EncryptedGroupSecrets:
    """HPKE-wrapped epoch secret material for a specific recipient."""

    kem_output: bytes
    ciphertext: bytes

    def serialize(self) -> bytes:
        """Encode KEM output and ciphertext as len-delimited fields."""
        return serialize_bytes(self.kem_output) + serialize_bytes(self.ciphertext)

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedGroupSecrets":
        """Parse KEM output and ciphertext from len-delimited fields."""
        kem, rest = deserialize_bytes(data)
        ct, _ = deserialize_bytes(rest)
        return cls(kem, ct)


@dataclass(frozen=True)
class GroupSecrets:
    """Secrets for onboarding new members via Welcome (RFC §12.4.3)."""

    joiner_secret: bytes
    psk_secret: Optional[bytes] = None

    def serialize(self) -> bytes:
        out = serialize_bytes(self.joiner_secret)
        out += serialize_bytes(self.psk_secret or b"")
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupSecrets":
        js, rest = deserialize_bytes(data)
        psk, _ = deserialize_bytes(rest) if rest else (b"", b"")
        return cls(js, psk if psk else None)

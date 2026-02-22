"""Core protocol data structures and (de)serialization helpers for MLS."""

from dataclasses import dataclass, field
from enum import IntEnum
from abc import ABC, abstractmethod
from typing import Optional
import struct

from ..codec.tls import (
    write_varint,
    read_varint,
    write_opaque_varint,
    read_opaque_varint,
    write_uint64,
    read_uint64,
)

from ..crypto.ciphersuites import KEM, KDF, AEAD, find_by_triple, get_ciphersuite_by_id
from ..mls.exceptions import RFC9420Error


def serialize_bytes(data: bytes) -> bytes:
    """Serialize bytes with a variable-length (varint) length prefix (RFC 9420 opaque<V>).

    Parameters:
        data: Payload to encode.

    Returns:
        Encoded bytes: varint length prefix followed by data.
    """
    return write_opaque_varint(data)


def deserialize_bytes(data: bytes) -> tuple[bytes, bytes]:
    """Deserialize bytes with a variable-length (varint) length prefix (opaque<V>).

    Parameters:
        data: Bytes starting with a varint length prefix followed by the payload.

    Returns:
        (payload, remainder) where payload is the decoded bytes and remainder
        is the unconsumed suffix of data after the encoded vector.
    """
    payload, new_offset = read_opaque_varint(data, 0)
    return payload, data[new_offset:]
    
# ... (skip to UpdatePath)




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
    certificates: list[bytes] = field(default_factory=list)

    def serialize(self) -> bytes:
        """Encode per RFC 9420 §5.3."""
        out = struct.pack("!H", self.credential_type.value)
        if self.credential_type == CredentialType.BASIC:
            out += write_opaque_varint(self.identity)
        elif self.credential_type == CredentialType.X509:
            # X.509: certificates is a vector of Certificate (opaque extension<V>)
            # Certificate certificates<V>;
            # specific encoding: a vector<V> of (opaque<V>)
            # First, serialize the vector content
            cert_list_data = b""
            for cert in self.certificates:
                cert_list_data += write_opaque_varint(cert)
            # Then prefix with the total length (vector<V>)
            out += write_varint(len(cert_list_data)) + cert_list_data
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "Credential":
        """Parse from uint16 credential_type || select(...)."""
        if len(data) < 2:
            # Legacy fallback: no credential_type prefix, treat as basic with opaque32
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
        if ct == CredentialType.BASIC:
            # Basic: opaque identity<V>
            # Try parsing as varint first
            try:
                identity, _ = read_opaque_varint(rest)
            except Exception:
                # Fallback / compatibility: existing code might produce 4-byte len
                identity, _ = deserialize_bytes(rest)
            return cls(identity, b"", ct)
        elif ct == CredentialType.X509:
            # X.509: Certificate certificates<V>;
            # First read the vector length
            total_len, offset = read_varint(rest)
            cert_data = rest[offset : offset + total_len]
            # Parse individual certificates
            certs = []
            while cert_data:
                cert, off = read_opaque_varint(cert_data)
                certs.append(cert)
                cert_data = cert_data[off:]
            return cls(b"", b"", ct, certificates=certs)
        
        # Fallback for unknown types (should not happen if enum covers all)
        return cls(b"", b"", ct)


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
        return write_opaque_varint(self.label or b"") + write_opaque_varint(self.content or b"")


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
        """Encode as uint16 proposal_type || content (RFC 9420 §12.1)."""
        return struct.pack("!H", self.proposal_type.value) + self._serialize_content()

    @classmethod
    def deserialize(cls, data: bytes) -> "Proposal":
        """Dispatch to the appropriate concrete Proposal subclass."""
        if len(data) < 2:
            raise RFC9420Error("Proposal too short for uint16 type")
        (proposal_type,) = struct.unpack("!H", data[:2])
        content = data[2:]

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

        Note: The caller (Proposal.deserialize) already strips the proposal
        type prefix before dispatching here. Stripping again is ambiguous and
        can corrupt valid KeyPackage bytes because KeyPackage starts with
        ProtocolVersion=0x0001, which collides with ProposalType.ADD.
        """
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
        """Construct from raw LeafNode bytes. Accepts raw content or full encoding (2-byte type + content)."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.UPDATE:
            data = data[2:]
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
        """Parse removed leaf index from uint32. Accepts raw content or full encoding (2-byte type + content)."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.REMOVE:
            data = data[2:]
        if len(data) < 4:
            raise RFC9420Error("RemoveProposal too short for uint32 removed")
        (removed,) = struct.unpack("!I", data[:4])
        return cls(removed)


class PSKType(IntEnum):
    """PSK Type (RFC 9420 §8.4)."""
    EXTERNAL = 1
    RESUMPTION = 2


class ResumptionPSKUsage(IntEnum):
    """Resumption PSK Usage (RFC 9420 §8.4)."""
    APPLICATION = 1
    REINIT = 2
    BRANCH = 3


@dataclass(frozen=True)
class PreSharedKeyID:
    """PreSharedKeyID structure (RFC 9420 §8.4).

    struct {
        PSKType psktype;
        select (PreSharedKeyID.psktype) {
            case external:
                opaque psk_id<V>;
            case resumption:
                ResumptionPSKUsage usage;
                opaque psk_group_id<V>;
                uint64 psk_epoch;
        };
        opaque psk_nonce<V>;
    } PreSharedKeyID;
    """
    psktype: PSKType
    psk_id: Optional[bytes] = None  # for external
    usage: Optional[ResumptionPSKUsage] = None  # for resumption
    psk_group_id: Optional[bytes] = None  # for resumption
    psk_epoch: Optional[int] = None  # for resumption
    psk_nonce: bytes = b""

    def serialize(self) -> bytes:
        out = struct.pack("!B", self.psktype.value)
        if self.psktype == PSKType.EXTERNAL:
            if self.psk_id is None:
                 raise RFC9420Error("PreSharedKeyID external missing psk_id")
            out += serialize_bytes(self.psk_id)
        elif self.psktype == PSKType.RESUMPTION:
            if self.usage is None or self.psk_group_id is None or self.psk_epoch is None:
                 raise RFC9420Error("PreSharedKeyID resumption missing fields")
            out += struct.pack("!B", self.usage.value)
            out += serialize_bytes(self.psk_group_id)
            out += write_uint64(self.psk_epoch)
        out += serialize_bytes(self.psk_nonce)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "tuple[PreSharedKeyID, bytes]":
        """Parse a PreSharedKeyID from the front of `data`. Returns (obj, remaining_bytes)."""
        if len(data) < 1:
            raise RFC9420Error("PreSharedKeyID too short")
        (type_val,) = struct.unpack("!B", data[:1])
        try:
            ptype = PSKType(type_val)
        except ValueError:
            raise RFC9420Error(f"Invalid PSKType: {type_val}")

        off = 1
        psk_id = None
        usage = None
        pgid = None
        pepoch = None

        if ptype == PSKType.EXTERNAL:
            psk_id, off = read_opaque_varint(data, off)
        elif ptype == PSKType.RESUMPTION:
            if off >= len(data):
                raise RFC9420Error("PreSharedKeyID resumption too short for usage")
            (u_val,) = struct.unpack("!B", data[off:off+1])
            off += 1
            try:
                usage = ResumptionPSKUsage(u_val)
            except ValueError:
                pass
            pgid, off = read_opaque_varint(data, off)
            pepoch, off = read_uint64(data, off)

        nonce, off = read_opaque_varint(data, off)
        return cls(ptype, psk_id, usage, pgid, pepoch, nonce), data[off:]



@dataclass(frozen=True)
class PreSharedKeyProposal(Proposal):
    """Proposal to bind a pre-shared key (PSK)."""

    psk: PreSharedKeyID

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.PRE_SHARED_KEY."""
        return ProposalType.PRE_SHARED_KEY

    def _serialize_content(self) -> bytes:
        """Encode PreSharedKeyID."""
        return self.psk.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "PreSharedKeyProposal":
        """Parse PreSharedKeyID. Accepts raw content or full encoding (2-byte type + content)."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.PRE_SHARED_KEY:
            data = data[2:]
        psk, _ = PreSharedKeyID.deserialize(data)  # returns (obj, remaining)
        return cls(psk)



@dataclass(frozen=True)
class ReInitProposal(Proposal):
    """Proposal to re-initialize the group (RFC 9420 §12.1.5).

    struct {
        opaque group_id<V>;
        ProtocolVersion version;
        CipherSuite cipher_suite;
        Extension extensions<V>;
    } ReInit;
    """

    new_group_id: bytes
    version: int = 0x0001  # mls10
    cipher_suite: int = 0x0001  # default; updated by caller
    extensions: bytes = b""  # serialized extension list

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.REINIT."""
        return ProposalType.REINIT

    def _serialize_content(self) -> bytes:
        """Encode group_id<V> || uint16 version || uint16 cipher_suite || extensions<V>."""
        out = serialize_bytes(self.new_group_id)
        out += struct.pack("!HH", self.version, self.cipher_suite)
        out += serialize_bytes(self.extensions)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "ReInitProposal":
        """Parse ReInit from len-delimited bytes. Accepts raw content or full encoding."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.REINIT:
            data = data[2:]
        gid, rest = deserialize_bytes(data)
        if len(rest) >= 4:
            version, cs_id = struct.unpack("!HH", rest[:4])
            ext, _ = deserialize_bytes(rest[4:]) if len(rest) > 4 else (b"", b"")
        else:
            # Legacy / minimal encoding (old code only sent group_id)
            version = 0x0001
            cs_id = 0x0001
            ext = b""
        return cls(gid, version, cs_id, ext)


@dataclass(frozen=True)
class ExternalInitProposal(Proposal):
    """Proposal to publish an external HPKE KEM output for external commits.
    
    RFC 9420 §12.4.3.4:
    struct {
        opaque kem_output<V>;
    } ExternalInit;
    """

    kem_output: bytes

    @property
    def proposal_type(self) -> ProposalType:
        """Return ProposalType.EXTERNAL_INIT."""
        return ProposalType.EXTERNAL_INIT

    def _serialize_content(self) -> bytes:
        """Encode kem_output as len-delimited bytes."""
        return serialize_bytes(self.kem_output)

    @classmethod
    def deserialize(cls, data: bytes) -> "ExternalInitProposal":
        """Parse kem_output from len-delimited bytes. Accepts raw content or full encoding (2-byte type + content)."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.EXTERNAL_INIT:
            data = data[2:]
        output, _ = deserialize_bytes(data)
        return cls(output)


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
        """Parse extensions from len-delimited bytes. Accepts raw content or full encoding (2-byte type + content)."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.GROUP_CONTEXT_EXTENSIONS:
            data = data[2:]
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
        """Parse authenticated_data from len-delimited bytes. Accepts raw content or full encoding (2-byte type + content)."""
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == ProposalType.APP_ACK:
            data = data[2:]
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
class UpdatePathNode:
    """Node in an UpdatePath (RFC 9420 §7.6).
    
    struct {
        HPKEPublicKey encryption_key;
        HPKECiphertext encrypted_path_secret<V>;
    } UpdatePathNode;
    """
    encryption_key: bytes
    encrypted_path_secrets: list[bytes] # encrypted_path_secret<V>

    def serialize(self) -> bytes:
        """Encode encryption_key and vector of encrypted path secrets."""
        data = serialize_bytes(self.encryption_key)
        # encrypted_path_secret<V>
        # First serialize the vector content
        eps_data = b""
        for eps in self.encrypted_path_secrets:
            # eps is the raw HPKECiphertext bytes
            eps_data += eps
        # Then prefix with total length (Varint)
        data += write_varint(len(eps_data)) + eps_data
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "UpdatePathNode":
        """Parse UpdatePathNode."""
        encryption_key, rest = deserialize_bytes(data)
        
        # Parse vector<V> of encrypted path secrets
        eps_len, offset = read_varint(rest, 0)
        rest = rest[offset:]
        eps_data = rest[:eps_len]
        
        secrets = []
        while eps_data:
            # Parse one HPKECiphertext (kem_output<V> || ciphertext<V>)
            kem_out, sub_off = read_opaque_varint(eps_data)
            ct, sub_off2 = read_opaque_varint(eps_data[sub_off:])
            total_len = sub_off + sub_off2
            
            # Reconstruct the raw bytes for the list
            cipher_blob = eps_data[:total_len]
            secrets.append(cipher_blob)
            
            eps_data = eps_data[total_len:]
        
        return cls(encryption_key, secrets)

    @classmethod
    def deserialize_impl(cls, data: bytes) -> tuple["UpdatePathNode", int]:
        """Helper to deserialize and return consumed length."""
        encryption_key, rest = deserialize_bytes(data)
        key_len = len(data) - len(rest)
        
        # Parse vector<V> of encrypted path secrets
        eps_len, offset = read_varint(rest, 0)
        # Total consumed for vector is offset + eps_len
        
        # Parse the node itself
        node = cls.deserialize(data[:key_len + offset + eps_len])
        return node, key_len + offset + eps_len

@dataclass(frozen=True)
class UpdatePath:
    """Commit path structure (RFC 9420 §7.6).
    
    struct {
        LeafNode leaf_node;
        UpdatePathNode nodes<V>;
    } UpdatePath;
    """

    leaf_node: bytes
    nodes: list[UpdatePathNode]

    def serialize(self) -> bytes:
        """Encode leaf_node and nodes vector."""
        # RFC 9420: LeafNode leaf_node; UpdatePathNode nodes<V>;
        # LeafNode is embedded directly (structure).
        data = self.leaf_node
        
        # nodes<V>
        nodes_data = b""
        for node in self.nodes:
            nodes_data += node.serialize()
            
        data += write_varint(len(nodes_data)) + nodes_data
        return data



    @classmethod
    def deserialize(cls, data: bytes) -> "UpdatePath":
        """Parse UpdatePath."""
        from .key_packages import LeafNode
        # Parse LeafNode (self-delimiting)
        # We need a LeafNode.deserialize that returns consumed bytes or object + rest.
        # Current LeafNode.deserialize consumes... well, it takes `data`.
        # It relies on fields being self-delimiting.
        # But `LeafNode.deserialize` currently returns just the object.
        # We need to know how much it consumed.
        # Workaround: Parsing `LeafNode` is complex.
        # But wait, `LeafNode` ends with `Signature` which is `opaque<V>` (raw bytes? No, signature is opaque<V>).
        # So it is self-delimiting.
        # We can try to parse it. Current `LeafNode.deserialize` might fail if extra data is present?
        # No, `deserialize_bytes` reads prefix.
        # `Extension` list is `extensions<V>`.
        # So if `LeafNode.deserialize` is robust, it works.
        # BUT `LeafNode.deserialize` implementation in `key_packages.py` does:
        # `enc_key, rest = deserialize_bytes(data)` etc.
        # It returns `cls(...)`. It does NOT return `rest`.
        # This is invalid for stream parsing.
        
        # I MUST update `LeafNode.deserialize` to return `(LeafNode, consumed)` OR handle it here.
        # Or I can cheat:
        # If I don't change `LeafNode` deserializer signature (to avoid breaking other calls),
        # I can guess length by re-serializing? That's what `FramedContent` does.
        
        leaf = LeafNode.deserialize(data)
        leaf_len = len(leaf.serialize())
        # Re-check verification? No.
        
        rest = data[leaf_len:]
        
        # Parse nodes<V>
        nodes_len, offset = read_varint(rest, 0)
        rest = rest[offset:]
        nodes_data = rest[:nodes_len]
        
        nodes = []
        while nodes_data:
            node, consumed = UpdatePathNode.deserialize_impl(nodes_data)
            nodes.append(node)
            nodes_data = nodes_data[consumed:]
            
        return cls(leaf.serialize(), nodes)



@dataclass(frozen=True)
class Commit:
    """Commit object carrying proposals and optional UpdatePath (RFC 9420 §12.2).
    
    struct {
        ProposalOrRef proposals<V>;
        optional<UpdatePath> path;
    } Commit;
    """

    path: Optional[UpdatePath]
    proposals: list[ProposalOrRef]

    def serialize(self) -> bytes:
        """Encode proposals vector<V> then optional path."""
        # Proposals vector<V>
        prop_data = b""
        for por in self.proposals:
            prop_data += por.serialize()
        data = write_varint(len(prop_data)) + prop_data

        # Optional UpdatePath
        if self.path:
            data += b"\x01"
            data += self.path.serialize()
        else:
            data += b"\x00"

        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Commit":
        """Parse Commit."""
        # Read proposals vector<V>
        if len(data) < 1:
             # Just proposals vector length?
             pass # handle via read_varint error or logic
             
        prop_len, offset = read_varint(data, 0)
        rest = data[offset:]
        if len(rest) < prop_len:
             raise RFC9420Error("Commit too short for proposals")
             
        props_data = rest[:prop_len]
        rest = rest[prop_len:]
        
        proposals: list[ProposalOrRef] = []
        while props_data:
            # Deserialize one ProposalOrRef
            # We need to determine its length.
            # ProposalOrRef starts with 1 byte type.
            # Then specialized content.
            # We can use ProposalOrRef.deserialize, then re-serialize to find length.
            por = ProposalOrRef.deserialize(props_data)
            por_len = len(por.serialize())
            proposals.append(por)
            props_data = props_data[por_len:]

        # Path presence
        if not rest:
             raise RFC9420Error("Commit missing path presence byte")
             
        present = rest[0]
        rest = rest[1:]
        path = None
        
        if present == 1:
            path = UpdatePath.deserialize(rest)
        elif present != 0:
            raise RFC9420Error("Invalid path presence byte")
            
        return cls(path, proposals)


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
        To-Be-Signed bytes for GroupInfo per RFC 9420 §12.4.3:
          GroupContext || extensions || confirmation_tag<V> || uint32 signer
        """
        out = self.group_context.serialize()
        out += serialize_bytes(self.extensions)
        out += serialize_bytes(self.confirmation_tag)
        out += struct.pack("!I", self.signer_leaf_index)
        return out

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
    """GroupSecrets per RFC 9420 §12.4.3.1.

    struct {
        opaque joiner_secret<V>;
        optional<PathSecret> path_secret;
        optional<PreSharedKeyID> psks<V>;
    } GroupSecrets;
    """

    joiner_secret: bytes
    psk_secret: Optional[bytes] = None   # kept for legacy but NOT serialized; use psks
    path_secret: Optional[bytes] = None  # committer's path_secret for fast-join (RFC §12.4.3.1)
    psks: "Optional[list[PreSharedKeyID]]" = None

    def serialize(self) -> bytes:
        """Encode per RFC 9420 §12.4.3.1."""
        out = serialize_bytes(self.joiner_secret)
        # optional path_secret: 0x01 || opaque<V> if present, else 0x00
        if self.path_secret is not None:
            out += b"\x01" + serialize_bytes(self.path_secret)
        else:
            out += b"\x00"
        # optional psks: 0x01 || vector<PreSharedKeyID> if present, else 0x00
        if self.psks:
            psks_data = b"".join(p.serialize() for p in self.psks)
            out += b"\x01" + serialize_bytes(psks_data)
        else:
            out += b"\x00"
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupSecrets":
        """Decode per RFC 9420 §12.4.3.1."""
        js, rest = deserialize_bytes(data)

        # optional path_secret
        path_secret = None
        if rest:
            present, rest = rest[0], rest[1:]
            if present == 1 and rest:
                path_secret, rest = deserialize_bytes(rest)

        # optional psks
        psks: "Optional[list[PreSharedKeyID]]" = None
        if rest:
            present, rest = rest[0], rest[1:]
            if present == 1 and rest:
                psks_blob, rest = deserialize_bytes(rest)
                psks = []
                while psks_blob:
                    psk_id_obj, psks_blob = PreSharedKeyID.deserialize(psks_blob)
                    psks.append(psk_id_obj)

        return cls(js, None, path_secret, psks)


# Helper for vector serialization
def serialize_vector(data: bytes) -> bytes:
    """Standard MLS opaque<V>: 4-byte big-endian length prefix."""
    return struct.pack("!I", len(data)) + data

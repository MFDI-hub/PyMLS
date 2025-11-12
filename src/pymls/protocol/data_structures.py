"""Core protocol data structures and (de)serialization helpers for MLS."""
from dataclasses import dataclass
from enum import Enum, IntEnum
from abc import ABC, abstractmethod
import struct

from ..crypto.hpke import KEM, KDF, AEAD
from ..mls.exceptions import PyMLSError


def serialize_bytes(data: bytes) -> bytes:
    """Serializes bytes with a 4-byte length prefix."""
    return struct.pack("!L", len(data)) + data


def deserialize_bytes(data: bytes) -> tuple[bytes, bytes]:
    """Deserializes bytes with a 4-byte length prefix."""
    length, = struct.unpack("!L", data[:4])
    return data[4:4+length], data[4+length:]


class MLSVersion(Enum):
    """Protocol version enumeration."""
    MLS10 = "mls10"


@dataclass(frozen=True)
class CipherSuite:
    """Selected KEM, KDF, and AEAD identifiers for an epoch."""
    kem: KEM
    kdf: KDF
    aead: AEAD

    def serialize(self) -> bytes:
        """Encode as uint16 kem || uint16 kdf || uint16 aead."""
        return struct.pack("!HHH", self.kem.value, self.kdf.value, self.aead.value)

    @classmethod
    def deserialize(cls, data: bytes) -> "CipherSuite":
        """Parse a CipherSuite from 6 bytes."""
        kem_val, kdf_val, aead_val = struct.unpack("!HHH", data)
        return cls(KEM(kem_val), KDF(kdf_val), AEAD(aead_val))


@dataclass(frozen=True)
class Sender:
    """Sender descriptor carrying the leaf index."""
    sender: int  # leaf index

    def serialize(self) -> bytes:
        """Encode as uint32 sender."""
        return struct.pack("!I", self.sender)

    @classmethod
    def deserialize(cls, data: bytes) -> "Sender":
        """Parse from 4-byte uint32."""
        sender, = struct.unpack("!I", data)
        return cls(sender)


@dataclass(frozen=True)
class Credential:
    """Basic credential carrying identity and signature public key."""
    identity: bytes
    public_key: bytes

    def serialize(self) -> bytes:
        """Encode as len-delimited identity || len-delimited public_key."""
        return serialize_bytes(self.identity) + serialize_bytes(self.public_key)

    @classmethod
    def deserialize(cls, data: bytes) -> "Credential":
        """Parse from len-delimited identity and public_key."""
        identity, rest = deserialize_bytes(data)
        public_key, _ = deserialize_bytes(rest)
        return cls(identity, public_key)


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


class ProposalType(IntEnum):
    """Enumeration of proposal kinds."""
    ADD = 1
    UPDATE = 2
    REMOVE = 3
    PRE_SHARED_KEY = 4
    REINIT = 5
    EXTERNAL_INIT = 6
    GROUP_CONTEXT_EXTENSIONS = 7


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
        proposal_type, = struct.unpack("!B", data[:1])
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

        raise PyMLSError(f"Unknown proposal type: {proposal_type}")


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
        """Construct from raw KeyPackage bytes."""
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
        """Construct from raw LeafNode bytes."""
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
        """Parse removed leaf index from uint32."""
        removed, = struct.unpack("!I", data)
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
        """Parse PSK identifier from len-delimited bytes."""
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
        """Parse new group_id from len-delimited bytes."""
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
        """Parse HPKE public key from len-delimited bytes."""
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
        """Parse extensions from len-delimited bytes."""
        ext, _ = deserialize_bytes(data)
        return cls(ext)

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
        num_nodes, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        nodes = {}
        for _ in range(num_nodes):
            key, = struct.unpack("!I", rest[:4])
            rest = rest[4:]
            num_recips, = struct.unpack("!H", rest[:2])
            rest = rest[2:]
            recips: list[bytes] = []
            for __ in range(num_recips):
                blob, rest = deserialize_bytes(rest)
                recips.append(blob)
            nodes[key] = recips
        return cls(leaf_node, nodes)

@dataclass(frozen=True)
class Commit:
    """Commit object carrying optional UpdatePath and proposal effects."""
    path: UpdatePath | None
    removes: list[int]
    adds: list[bytes]  # Serialized KeyPackages
    proposal_refs: list[bytes]
    signature: Signature

    def serialize(self) -> bytes:
        """Encode presence of path, removes/adds lists, proposal_refs, and signature."""
        data = b""
        if self.path:
            data += b'\x01'
            data += serialize_bytes(self.path.serialize())
        else:
            data += b'\x00'

        data += struct.pack("!H", len(self.removes))
        for item in self.removes:
            data += struct.pack("!I", item)

        data += struct.pack("!H", len(self.adds))
        for item in self.adds:
            data += serialize_bytes(item)

        # proposal references
        data += struct.pack("!H", len(self.proposal_refs))
        for pref in self.proposal_refs:
            data += serialize_bytes(pref)

        data += self.signature.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Commit":
        """Parse a Commit from bytes produced by serialize()."""
        has_path = (data[0] == 1)
        rest = data[1:]
        path = None
        if has_path:
            path_bytes, rest = deserialize_bytes(rest)
            path = UpdatePath.deserialize(path_bytes)

        num_removes, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        removes = []
        for _ in range(num_removes):
            item, = struct.unpack("!I", rest[:4])
            removes.append(item)
            rest = rest[4:]

        num_adds, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        adds = []
        for _ in range(num_adds):
            item, rest = deserialize_bytes(rest)
            adds.append(item)

        num_refs, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        refs = []
        for _ in range(num_refs):
            pref, rest = deserialize_bytes(rest)
            refs.append(pref)

        signature = Signature.deserialize(rest)
        return cls(path, removes, adds, refs, signature)


@dataclass(frozen=True)
class Welcome:
    """Welcome message carrying epoch secrets and encrypted GroupInfo."""
    version: MLSVersion
    cipher_suite: CipherSuite
    secrets: list["EncryptedGroupSecrets"]
    encrypted_group_info: bytes

    def serialize(self) -> bytes:
        """Encode version, cipher suite, secrets, and encrypted GroupInfo."""
        data = serialize_bytes(self.version.value.encode('utf-8'))
        data += self.cipher_suite.serialize()

        data += struct.pack("!H", len(self.secrets))
        for secret in self.secrets:
            data += serialize_bytes(secret.serialize())

        data += serialize_bytes(self.encrypted_group_info)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Welcome":
        """Parse a Welcome from bytes produced by serialize()."""
        version_bytes, rest = deserialize_bytes(data)
        version = MLSVersion(version_bytes.decode('utf-8'))

        cipher_suite = CipherSuite.deserialize(rest[:6])
        rest = rest[6:]

        num_secrets, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        secrets: list[EncryptedGroupSecrets] = []
        for _ in range(num_secrets):
            sbytes, rest = deserialize_bytes(rest)
            secrets.append(EncryptedGroupSecrets.deserialize(sbytes))

        encrypted_group_info, _ = deserialize_bytes(rest)

        return cls(version, cipher_suite, secrets, encrypted_group_info)


@dataclass(frozen=True)
class GroupContext:
    """Group context bound into key schedule and transcript computation."""
    group_id: bytes
    epoch: int
    tree_hash: bytes
    confirmed_transcript_hash: bytes

    def serialize(self) -> bytes:
        """Encode as uint64 epoch || group_id || tree_hash || confirmed_transcript_hash."""
        data = struct.pack("!Q", self.epoch)
        data += serialize_bytes(self.group_id)
        data += serialize_bytes(self.tree_hash)
        data += serialize_bytes(self.confirmed_transcript_hash)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupContext":
        """Parse GroupContext from bytes produced by serialize()."""
        epoch, = struct.unpack("!Q", data[:8])
        rest = data[8:]
        group_id, rest = deserialize_bytes(rest)
        tree_hash, rest = deserialize_bytes(rest)
        confirmed_transcript_hash, _ = deserialize_bytes(rest)
        return cls(group_id, epoch, tree_hash, confirmed_transcript_hash)


@dataclass(frozen=True)
class GroupInfo:
    """Signed GroupContext and optional extensions referenced by Welcome."""
    group_context: GroupContext
    signature: Signature
    extensions: bytes = b""  # serialized extensions (opaque); MVP keeps raw for flexibility

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
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupInfo":
        """Parse GroupInfo from bytes produced by serialize()."""
        gc_bytes, rest = deserialize_bytes(data)
        sig_bytes, rest = deserialize_bytes(rest)
        ext_bytes, _ = deserialize_bytes(rest) if rest else (b"", b"")
        group_context = GroupContext.deserialize(gc_bytes)
        signature = Signature.deserialize(sig_bytes)
        return cls(group_context, signature, ext_bytes)


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




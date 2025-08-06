from dataclasses import dataclass
from enum import Enum, IntEnum
from abc import ABC, abstractmethod
import struct

from ..crypto.hpke import KEM, KDF, AEAD


def serialize_bytes(data: bytes) -> bytes:
    """Serializes bytes with a 4-byte length prefix."""
    return struct.pack("!L", len(data)) + data


def deserialize_bytes(data: bytes) -> tuple[bytes, bytes]:
    """Deserializes bytes with a 4-byte length prefix."""
    length, = struct.unpack("!L", data[:4])
    return data[4:4+length], data[4+length:]


class MLSVersion(Enum):
    MLS10 = "mls10"


@dataclass(frozen=True)
class CipherSuite:
    kem: KEM
    kdf: KDF
    aead: AEAD

    def serialize(self) -> bytes:
        return struct.pack("!HHH", self.kem.value, self.kdf.value, self.aead.value)

    @classmethod
    def deserialize(cls, data: bytes) -> "CipherSuite":
        kem_val, kdf_val, aead_val = struct.unpack("!HHH", data)
        return cls(KEM(kem_val), KDF(kdf_val), AEAD(aead_val))


@dataclass(frozen=True)
class Sender:
    sender: int  # leaf index

    def serialize(self) -> bytes:
        return struct.pack("!I", self.sender)

    @classmethod
    def deserialize(cls, data: bytes) -> "Sender":
        sender, = struct.unpack("!I", data)
        return cls(sender)


@dataclass(frozen=True)
class Credential:
    identity: bytes
    public_key: bytes

    def serialize(self) -> bytes:
        return serialize_bytes(self.identity) + serialize_bytes(self.public_key)

    @classmethod
    def deserialize(cls, data: bytes) -> "Credential":
        identity, rest = deserialize_bytes(data)
        public_key, _ = deserialize_bytes(rest)
        return cls(identity, public_key)


@dataclass(frozen=True)
class Signature:
    value: bytes

    def serialize(self) -> bytes:
        return self.value

    @classmethod
    def deserialize(cls, data: bytes) -> "Signature":
        return cls(data)


class ProposalType(IntEnum):
    ADD = 1
    UPDATE = 2
    REMOVE = 3


class Proposal(ABC):
    @property
    @abstractmethod
    def proposal_type(self) -> ProposalType:
        raise NotImplementedError

    @abstractmethod
    def _serialize_content(self) -> bytes:
        raise NotImplementedError

    def serialize(self) -> bytes:
        return struct.pack("!B", self.proposal_type.value) + self._serialize_content()

    @classmethod
    def deserialize(cls, data: bytes) -> "Proposal":
        proposal_type, = struct.unpack("!B", data[:1])
        content = data[1:]

        if proposal_type == ProposalType.ADD:
            return AddProposal.deserialize(content)
        if proposal_type == ProposalType.UPDATE:
            return UpdateProposal.deserialize(content)
        if proposal_type == ProposalType.REMOVE:
            return RemoveProposal.deserialize(content)

        raise ValueError(f"Unknown proposal type: {proposal_type}")


@dataclass(frozen=True)
class AddProposal(Proposal):
    key_package: bytes

    @property
    def proposal_type(self) -> ProposalType:
        return ProposalType.ADD

    def _serialize_content(self) -> bytes:
        return self.key_package

    @classmethod
    def deserialize(cls, data: bytes) -> "AddProposal":
        return cls(data)


@dataclass(frozen=True)
class UpdateProposal(Proposal):
    leaf_node: bytes

    @property
    def proposal_type(self) -> ProposalType:
        return ProposalType.UPDATE

    def _serialize_content(self) -> bytes:
        return self.leaf_node

    @classmethod
    def deserialize(cls, data: bytes) -> "UpdateProposal":
        return cls(data)


@dataclass(frozen=True)
class RemoveProposal(Proposal):
    removed: int

    @property
    def proposal_type(self) -> ProposalType:
        return ProposalType.REMOVE

    def _serialize_content(self) -> bytes:
        return struct.pack("!I", self.removed)

    @classmethod
    def deserialize(cls, data: bytes) -> "RemoveProposal":
        removed, = struct.unpack("!I", data)
        return cls(removed)

@dataclass(frozen=True)
class UpdatePath:
    leaf_node: bytes
    nodes: dict[int, bytes]

    def serialize(self) -> bytes:
        data = serialize_bytes(self.leaf_node)
        data += struct.pack("!H", len(self.nodes))
        for key, value in self.nodes.items():
            data += struct.pack("!I", key)
            data += serialize_bytes(value)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "UpdatePath":
        leaf_node, rest = deserialize_bytes(data)
        num_nodes, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        nodes = {}
        for _ in range(num_nodes):
            key, = struct.unpack("!I", rest[:4])
            rest = rest[4:]
            value, rest = deserialize_bytes(rest)
            nodes[key] = value
        return cls(leaf_node, nodes)

@dataclass(frozen=True)
class Commit:
    path: UpdatePath | None
    removes: list[int]
    adds: list[bytes]  # Serialized KeyPackages
    signature: Signature

    def serialize(self) -> bytes:
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

        data += self.signature.serialize()
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Commit":
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

        signature = Signature.deserialize(rest)
        return cls(path, removes, adds, signature)


@dataclass(frozen=True)
class Welcome:
    version: MLSVersion
    cipher_suite: CipherSuite
    secrets: list[bytes]
    encrypted_group_info: bytes

    def serialize(self) -> bytes:
        data = serialize_bytes(self.version.value.encode('utf-8'))
        data += self.cipher_suite.serialize()

        data += struct.pack("!H", len(self.secrets))
        for secret in self.secrets:
            data += serialize_bytes(secret)

        data += serialize_bytes(self.encrypted_group_info)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "Welcome":
        version_bytes, rest = deserialize_bytes(data)
        version = MLSVersion(version_bytes.decode('utf-8'))

        cipher_suite = CipherSuite.deserialize(rest[:6])
        rest = rest[6:]

        num_secrets, = struct.unpack("!H", rest[:2])
        rest = rest[2:]
        secrets = []
        for _ in range(num_secrets):
            secret, rest = deserialize_bytes(rest)
            secrets.append(secret)

        encrypted_group_info, _ = deserialize_bytes(rest)

        return cls(version, cipher_suite, secrets, encrypted_group_info)


@dataclass(frozen=True)
class GroupContext:
    group_id: bytes
    epoch: int
    tree_hash: bytes
    confirmed_transcript_hash: bytes

    def serialize(self) -> bytes:
        data = struct.pack("!Q", self.epoch)
        data += serialize_bytes(self.group_id)
        data += serialize_bytes(self.tree_hash)
        data += serialize_bytes(self.confirmed_transcript_hash)
        return data

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupContext":
        epoch, = struct.unpack("!Q", data[:8])
        rest = data[8:]
        group_id, rest = deserialize_bytes(rest)
        tree_hash, rest = deserialize_bytes(rest)
        confirmed_transcript_hash, _ = deserialize_bytes(rest)
        return cls(group_id, epoch, tree_hash, confirmed_transcript_hash)


@dataclass(frozen=True)
class GroupInfo:
    group_context: GroupContext
    signature: Signature

    def serialize(self) -> bytes:
        return serialize_bytes(self.group_context.serialize()) + self.signature.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "GroupInfo":
        gc_bytes, rest = deserialize_bytes(data)
        group_context = GroupContext.deserialize(gc_bytes)
        signature = Signature.deserialize(rest)
        return cls(group_context, signature)




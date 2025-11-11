from dataclasses import dataclass
import struct

from .data_structures import Signature


@dataclass(frozen=True)
class PublicMessage:
    content: bytes
    signature: Signature

    def serialize(self) -> bytes:
        return self.content + self.signature.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "PublicMessage":
        # This is a simplification
        content = data[:-64]
        signature = Signature.deserialize(data[-64:])
        return cls(content, signature)


@dataclass(frozen=True)
class PrivateMessage:
    ciphertext: bytes
    auth_tag: bytes

    def serialize(self) -> bytes:
        return self.ciphertext + self.auth_tag

    @classmethod
    def deserialize(cls, data: bytes) -> "PrivateMessage":
        # This is a simplification
        ciphertext = data[:-16]
        auth_tag = data[-16:]
        return cls(ciphertext, auth_tag)

# --- RFC 9420 message framing (new API) ---

from enum import IntEnum
from ..codec.tls import (
    write_uint8,
    write_uint16,
    write_uint32,
    write_opaque16,
    read_uint8,
    read_uint16,
    read_uint32,
    read_opaque16,
)
from .key_schedule import KeySchedule
from ..crypto.crypto_provider import CryptoProvider


class ContentType(IntEnum):
    APPLICATION = 1
    PROPOSAL = 2
    COMMIT = 3


@dataclass(frozen=True)
class FramedContent:
    content_type: ContentType
    content: bytes  # RFC: ApplicationData | Proposal | Commit

    def serialize(self) -> bytes:
        return write_uint8(int(self.content_type)) + write_opaque16(self.content)

    @classmethod
    def deserialize(cls, data: bytes) -> "FramedContent":
        off = 0
        ct_val, off = read_uint8(data, off)
        body, off = read_opaque16(data, off)
        return cls(ContentType(ct_val), body)


@dataclass(frozen=True)
class AuthenticatedContentTBS:
    # To-Be-Signed structure
    group_id: bytes
    epoch: int
    sender_leaf_index: int
    authenticated_data: bytes
    framed_content: FramedContent

    def serialize(self) -> bytes:
        out = write_opaque16(self.group_id)
        out += write_uint32(self.epoch)
        out += write_uint16(self.sender_leaf_index)
        out += write_opaque16(self.authenticated_data)
        out += self.framed_content.serialize()
        return out


@dataclass(frozen=True)
class AuthenticatedContent:
    tbs: AuthenticatedContentTBS
    signature: bytes
    membership_tag: bytes | None = None

    def serialize(self) -> bytes:
        out = self.tbs.serialize()
        out += write_opaque16(self.signature)
        if self.membership_tag is not None:
            out += write_opaque16(self.membership_tag)
        else:
            out += write_uint16(0)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "AuthenticatedContent":
        off = 0
        group_id, off = read_opaque16(data, off)
        epoch, off = read_uint32(data, off)
        sender_idx, off = read_uint16(data, off)
        ad, off = read_opaque16(data, off)
        fc = FramedContent.deserialize(data[off:])
        # Compute new offset by re-serializing framed content's length
        fc_ser = fc.serialize()
        off += len(fc_ser)
        sig, off = read_opaque16(data, off)
        mtag, off = read_opaque16(data, off)
        tbs = AuthenticatedContentTBS(group_id, epoch, sender_idx, ad, fc)
        return cls(tbs, sig, mtag if len(mtag) > 0 else None)


@dataclass(frozen=True)
class MLSPlaintext:
    auth_content: AuthenticatedContent

    def serialize(self) -> bytes:
        return self.auth_content.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "MLSPlaintext":
        return cls(AuthenticatedContent.deserialize(data))


@dataclass(frozen=True)
class SenderData:
    sender: int
    generation: int
    reuse_guard: bytes

    def serialize(self) -> bytes:
        out = write_uint16(self.sender)
        out += write_uint32(self.generation)
        out += write_opaque16(self.reuse_guard)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "SenderData":
        off = 0
        s, off = read_uint16(data, off)
        g, off = read_uint32(data, off)
        rg, off = read_opaque16(data, off)
        return cls(s, g, rg)


@dataclass(frozen=True)
class MLSCiphertext:
    group_id: bytes
    epoch: int
    content_type: ContentType
    authenticated_data: bytes
    encrypted_sender_data: bytes
    ciphertext: bytes

    def serialize(self) -> bytes:
        out = write_opaque16(self.group_id)
        out += write_uint32(self.epoch)
        out += write_uint8(int(self.content_type))
        out += write_opaque16(self.authenticated_data)
        out += write_opaque16(self.encrypted_sender_data)
        out += write_opaque16(self.ciphertext)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "MLSCiphertext":
        off = 0
        gid, off = read_opaque16(data, off)
        epoch, off = read_uint32(data, off)
        ct, off = read_uint8(data, off)
        ad, off = read_opaque16(data, off)
        esd, off = read_opaque16(data, off)
        body, off = read_opaque16(data, off)
        return cls(gid, epoch, ContentType(ct), ad, esd, body)


def encrypt_sender_data(
    sd: SenderData, key_schedule: KeySchedule, crypto: CryptoProvider, aad: bytes = b""
) -> bytes:
    key = key_schedule.sender_data_key()
    nonce = key_schedule.sender_data_nonce(sd.reuse_guard)
    return crypto.aead_encrypt(key, nonce, sd.serialize(), aad)


def decrypt_sender_data(
    enc: bytes, reuse_guard: bytes, key_schedule: KeySchedule, crypto: CryptoProvider, aad: bytes = b""
) -> SenderData:
    key = key_schedule.sender_data_key()
    nonce = key_schedule.sender_data_nonce(reuse_guard)
    ptxt = crypto.aead_decrypt(key, nonce, enc, aad)
    return SenderData.deserialize(ptxt)


# AAD and padding helpers
def compute_ciphertext_aad(group_id: bytes, epoch: int, content_type: ContentType, authenticated_data: bytes) -> bytes:
    """
    RFC-style AAD for MLSCiphertext content encryption.
    """
    out = write_opaque16(group_id)
    out += write_uint32(epoch)
    out += write_uint8(int(content_type))
    out += write_opaque16(authenticated_data)
    return out


def add_zero_padding(data: bytes, pad_to: int) -> bytes:
    if pad_to <= 0:
        return data
    rem = len(data) % pad_to
    need = (pad_to - rem) % pad_to
    if need == 0:
        return data
    return data + (b"\x00" * need)


def strip_trailing_zeros(data: bytes) -> bytes:
    return data.rstrip(b"\x00")
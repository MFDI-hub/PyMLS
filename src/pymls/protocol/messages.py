from dataclasses import dataclass
import struct
import os

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
class PSKPreimage:
    """
    Simplified PSK preimage: list of PSK identifiers encoded as opaque16.
    """
    psk_ids: list[bytes]

    def serialize(self) -> bytes:
        out = write_uint16(len(self.psk_ids))
        for pid in self.psk_ids:
            out += write_opaque16(pid)
        return out

def encode_psk_binder(binder: bytes) -> bytes:
    """
    Encode a PSK binder into authenticated_data. Magic prefix + opaque16.
    """
    return b"PSKB" + write_opaque16(binder)

def decode_psk_binder(authenticated_data: bytes) -> bytes | None:
    """
    Decode a PSK binder from authenticated_data if present.
    Returns binder bytes or None.
    """
    if not authenticated_data or len(authenticated_data) < 4:
        return None
    if not authenticated_data.startswith(b"PSKB"):
        return None
    # read binder after 4-byte prefix
    _, off = read_uint8(b"\x00", 0)  # no-op to access read_opaque16 signature
    binder, _ = read_opaque16(authenticated_data, 4)
    return binder


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


def encode_encrypted_sender_data(
    sd: SenderData, key_schedule: KeySchedule, crypto: CryptoProvider
) -> bytes:
    """
    Encode encrypted sender data as a single opaque field containing:
      reuse_guard || enc(SenderData)
    """
    enc = encrypt_sender_data(sd, key_schedule, crypto, aad=b"")
    return write_opaque16(sd.reuse_guard + enc)


def decode_encrypted_sender_data(
    data: bytes, key_schedule: KeySchedule, crypto: CryptoProvider
) -> SenderData:
    blob, _ = read_opaque16(data, 0)
    # first 4 bytes are reuse_guard, remainder is ciphertext
    reuse_guard = blob[:4]
    enc = blob[4:]
    return decrypt_sender_data(enc, reuse_guard, key_schedule, crypto, aad=b"")


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


# --- Helpers for signing and membership tags (RFC-aligned surface for MVP) ---
def apply_application_padding(data: bytes, block: int = 32) -> bytes:
    """
    Add randomized padding so that (len(data) + 1 + pad_len) % block == 0.
    The last byte encodes pad_len (0..255), and the pad bytes are random.
    """
    if block <= 0:
        return data + b"\x00"
    # Space for length byte
    rem = (len(data) + 1) % block
    need = (block - rem) % block
    if need > 255:
        # Cap to 255 to fit in one byte
        need = need % 256
    pad = os.urandom(need) if need > 0 else b""
    return data + pad + bytes([need])


def remove_application_padding(padded: bytes) -> bytes:
    """
    Remove padding added by apply_application_padding.
    """
    if not padded:
        return padded
    pad_len = padded[-1]
    if pad_len > len(padded) - 1:
        # Malformed; return as-is
        return padded
    return padded[: len(padded) - 1 - pad_len]
def sign_authenticated_content(
    group_id: bytes,
    epoch: int,
    sender_leaf_index: int,
    authenticated_data: bytes,
    content_type: ContentType,
    content: bytes,
    signing_private_key: bytes,
    crypto: CryptoProvider,
) -> MLSPlaintext:
    """
    Build MLSPlaintext by signing AuthenticatedContentTBS. Membership tag is left empty
    for the caller to attach via attach_membership_tag(), since it depends on the group
    membership key maintained by the group state.
    """
    framed = FramedContent(content_type=content_type, content=content)
    tbs = AuthenticatedContentTBS(
        group_id=group_id,
        epoch=epoch,
        sender_leaf_index=sender_leaf_index,
        authenticated_data=authenticated_data,
        framed_content=framed,
    )
    sig = crypto.sign(signing_private_key, tbs.serialize())
    auth = AuthenticatedContent(tbs=tbs, signature=sig, membership_tag=None)
    return MLSPlaintext(auth)


def attach_membership_tag(plaintext: MLSPlaintext, membership_key: bytes, crypto: CryptoProvider) -> MLSPlaintext:
    """
    Compute membership tag as HMAC over the serialized TBS (MVP behavior).
    """
    tag = crypto.hmac_sign(membership_key, plaintext.auth_content.tbs.serialize())
    return MLSPlaintext(AuthenticatedContent(tbs=plaintext.auth_content.tbs, signature=plaintext.auth_content.signature, membership_tag=tag))


def verify_plaintext(
    plaintext: MLSPlaintext,
    sender_signature_key: bytes,
    membership_key: bytes | None,
    crypto: CryptoProvider,
) -> None:
    """
    Verify signature and (if provided) membership tag of an MLSPlaintext.
    Raises on failure.
    """
    tbs_ser = plaintext.auth_content.tbs.serialize()
    crypto.verify(sender_signature_key, tbs_ser, plaintext.auth_content.signature)
    if membership_key is not None:
        tag = crypto.hmac_sign(membership_key, tbs_ser)
        if plaintext.auth_content.membership_tag is None or plaintext.auth_content.membership_tag != tag:
            raise ValueError("invalid membership tag")


# --- High-level content protection helpers (MVP) ---
def protect_content_handshake(
    group_id: bytes,
    epoch: int,
    sender_leaf_index: int,
    authenticated_data: bytes,
    content: bytes,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
) -> MLSCiphertext:
    """
    Encrypt handshake content using the secret tree handshake branch and sender data secret.
    Note: This MVP uses a reuse_guard embedded in SenderData and encrypts SenderData using
    the sender data secret. The derivation matches KeySchedule.sender_data_nonce() usage.
    """
    # Obtain per-sender handshake key/nonce and generation
    key, nonce, generation = secret_tree.next_handshake(sender_leaf_index)
    # Random reuse guard to diversify sender-data nonce
    reuse_guard = os.urandom(4)
    sd = SenderData(sender=sender_leaf_index, generation=generation, reuse_guard=reuse_guard)
    aad = compute_ciphertext_aad(group_id, epoch, ContentType.COMMIT, authenticated_data)
    enc_sd = encode_encrypted_sender_data(sd, key_schedule, crypto)
    ct = crypto.aead_encrypt(key, nonce, content, aad)
    return MLSCiphertext(
        group_id=group_id,
        epoch=epoch,
        content_type=ContentType.COMMIT,
        authenticated_data=authenticated_data,
        encrypted_sender_data=enc_sd,
        ciphertext=ct,
    )


def protect_content_application(
    group_id: bytes,
    epoch: int,
    sender_leaf_index: int,
    authenticated_data: bytes,
    content: bytes,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
) -> MLSCiphertext:
    """
    Encrypt application content using the secret tree application branch and sender data secret.
    """
    key, nonce, generation = secret_tree.next_application(sender_leaf_index)
    reuse_guard = os.urandom(4)
    sd = SenderData(sender=sender_leaf_index, generation=generation, reuse_guard=reuse_guard)
    aad = compute_ciphertext_aad(group_id, epoch, ContentType.APPLICATION, authenticated_data)
    enc_sd = encode_encrypted_sender_data(sd, key_schedule, crypto)
    # Apply RFC-style randomized padding to 32-byte boundary (simple scheme: random bytes + 1-byte length)
    padded = apply_application_padding(content, block=32)
    ct = crypto.aead_encrypt(key, nonce, padded, aad)
    return MLSCiphertext(
        group_id=group_id,
        epoch=epoch,
        content_type=ContentType.APPLICATION,
        authenticated_data=authenticated_data,
        encrypted_sender_data=enc_sd,
        ciphertext=ct,
    )


def unprotect_content_handshake(
    m: MLSCiphertext,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
) -> tuple[int, bytes]:
    """
    Decrypt handshake content and return (sender_leaf_index, plaintext).
    """
    aad = compute_ciphertext_aad(m.group_id, m.epoch, m.content_type, m.authenticated_data)
    sd = decode_encrypted_sender_data(m.encrypted_sender_data, key_schedule, crypto)
    key, nonce, _ = secret_tree.handshake_for(sd.sender, sd.generation)
    ptxt = crypto.aead_decrypt(key, nonce, m.ciphertext, aad)
    return sd.sender, ptxt


def unprotect_content_application(
    m: MLSCiphertext,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
) -> tuple[int, bytes]:
    """
    Decrypt application content and return (sender_leaf_index, plaintext).
    """
    aad = compute_ciphertext_aad(m.group_id, m.epoch, m.content_type, m.authenticated_data)
    sd = decode_encrypted_sender_data(m.encrypted_sender_data, key_schedule, crypto)
    key, nonce, _ = secret_tree.application_for(sd.sender, sd.generation)
    ptxt = crypto.aead_decrypt(key, nonce, m.ciphertext, aad)
    # Strip RFC-style padding
    return sd.sender, remove_application_padding(ptxt)
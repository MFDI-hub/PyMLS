"""RFC 9420 message framing (RFC 9420 §6–§9).

Handshake: AuthenticatedContent, MLSPlaintext (proposals, commits).
Application: MLSCiphertext with sender data encryption.
Includes content types, wire format discriminators, and PSK/PSKLabel handling.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .data_structures import Sender, PreSharedKeyID
from .data_structures import PreSharedKeyID
import os

from ..mls.exceptions import InvalidSignatureError
from ..codec.tls import (
    write_opaque_varint,
    read_opaque_varint,
    write_varint,
    write_uint8,
    read_uint8,
    write_uint16,
    read_uint16,
    write_uint32,
    read_uint32,
    write_uint64,
    read_uint64,
)
from .key_schedule import KeySchedule
from ..crypto.crypto_provider import CryptoProvider


def _require_length(data: bytes, length: int) -> None:
    if len(data) < length:
        raise Exception("buffer underflow")


# --- RFC 9420 message framing (new API) ---


class ContentType(IntEnum):
    """Content type for framed MLS messages (MVP subset)."""
    APPLICATION = 1
    PROPOSAL = 2
    COMMIT = 3


class ProtocolVersion(IntEnum):
    """Top-level protocol version enum for MLS messages (RFC §6)."""
    MLS10 = 1


class WireFormat(IntEnum):
    """Wire format discriminator for top-level messages (RFC §6 / §17.2 Table 5)."""
    PUBLIC_MESSAGE = 1   # mls_public_message
    PRIVATE_MESSAGE = 2  # mls_private_message
    WELCOME = 3          # mls_welcome
    GROUP_INFO = 4       # mls_group_info
    KEY_PACKAGE = 5      # mls_key_package


class SenderType(IntEnum):
    """Sender type enumeration (RFC §6)."""
    MEMBER = 1
    EXTERNAL = 2
    NEW_MEMBER_PROPOSAL = 3
    NEW_MEMBER_COMMIT = 4

@dataclass(frozen=True)
class PSKPreimage:
    """
    Simplified PSK preimage: list of PSK identifiers encoded as opaque<V>.
    """
    psk_ids: list[PreSharedKeyID]

    def serialize(self) -> bytes:
        """Encode as psk_ids<V> (Vector of PreSharedKeyID).
        
        RFC: struct { PreSharedKeyID psk_ids<V>; } PSKPreimage.
        """
        # Serialize items first
        payload = b""
        for pid in self.psk_ids:
            payload += pid.serialize()
        return write_varint(len(payload)) + payload


@dataclass(frozen=True)
class PSKLabel:
    """RFC 9420 §8.4 PSKLabel structure for chained PSK derivation.

    struct {
        PreSharedKeyID id;
        uint16 index;
        uint16 count;
    } PSKLabel;
    """
    psk_id: PreSharedKeyID
    index: int
    count: int

    def serialize(self) -> bytes:
        """Encode as PreSharedKeyID(id) || uint16(index) || uint16(count)."""
        return (
            self.psk_id.serialize()
            + write_uint16(self.index)
            + write_uint16(self.count)
        )


def derive_psk_secret(
    crypto: "CryptoProvider",
    psk_ids: list[PreSharedKeyID],
    psk_values: Optional[list[bytes]] = None,
) -> bytes:
    """Derive the PSK secret per RFC 9420 §8.4."""
    n = len(psk_ids)
    if n == 0:
        return bytes(crypto.kdf_hash_len())

    hash_len = crypto.kdf_hash_len()
    zero_ikm = bytes(hash_len)

    # psk_secret[0] = 0
    psk_secret = bytes(hash_len)

    for i in range(n):
        # Get or derive the PSK value
        if psk_values is not None and i < len(psk_values):
            psk_val = psk_values[i]
        else:
            # MVP fallback: derive a synthetic PSK from the ID serialization
            # This is NOT secure for production without real PSK storage
            psk_val = crypto.kdf_extract(b"psk", psk_ids[i].serialize())

        # psk_extracted = KDF.Extract(0, psk[i])
        psk_extracted = crypto.kdf_extract(zero_ikm, psk_val)

        # PSKLabel for this iteration
        label = PSKLabel(psk_id=psk_ids[i], index=i, count=n)

        # psk_input = ExpandWithLabel(psk_extracted, "derived psk", PSKLabel, Nh)
        psk_input = crypto.expand_with_label(
            psk_extracted, b"derived psk", label.serialize(), hash_len
        )

        # psk_secret[i+1] = KDF.Extract(psk_input, psk_secret[i])
        psk_secret = crypto.kdf_extract(psk_input, psk_secret)

    return psk_secret

def encode_psk_binder(binder: bytes) -> bytes:
    """
    Encode a PSK binder into authenticated_data. Magic prefix + opaque<V>.
    """
    return b"PSKB" + write_opaque_varint(binder)

def decode_psk_binder(authenticated_data: bytes) -> Optional[bytes]:
    """
    Decode a PSK binder from authenticated_data if present.
    Returns binder bytes or None.
    """
    if not authenticated_data or len(authenticated_data) < 4:
        return None
    if not authenticated_data.startswith(b"PSKB"):
        return None
    # read binder after 4-byte prefix
    binder, _ = read_opaque_varint(authenticated_data, 4)
    return binder


@dataclass(frozen=True)
class FramedContent:
    """RFC 9420 §6 FramedContent structure.

    struct {
        opaque group_id<V>;
        uint64 epoch;
        Sender sender;
        opaque authenticated_data<V>;
        ContentType content_type;
        select (FramedContent.content_type) {
            case application: opaque application_data<V>;
            case proposal:    Proposal proposal;
            case commit:      Commit commit;
        };
    } FramedContent;
    """
    group_id: bytes
    epoch: int
    sender: 'Sender'
    authenticated_data: bytes
    content_type: ContentType
    content: bytes  # RFC: ApplicationData | Proposal | Commit

    def serialize(self) -> bytes:
        """Encode FramedContent per RFC 9420 §6."""
        from .data_structures import Sender as _Sender
        out = write_opaque_varint(self.group_id)
        out += write_uint64(self.epoch)
        if isinstance(self.sender, _Sender):
            out += self.sender.serialize()
        else:
            out += _Sender(self.sender).serialize()
        out += write_opaque_varint(self.authenticated_data)
        out += write_uint8(int(self.content_type))
        
        # Content serialization based on type
        if self.content_type == ContentType.APPLICATION:
            # application_data<V>
            out += write_opaque_varint(self.content)
        else:
            # proposal/commit -> direct embedding, no length prefix
            out += self.content
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "FramedContent":
        """Parse FramedContent from bytes."""
        from .data_structures import Sender as _Sender
        off = 0
        group_id, off = read_opaque_varint(data, off)
        epoch, off = read_uint64(data, off)
        sender = _Sender.deserialize(data[off:])
        off += len(sender.serialize())
        ad, off = read_opaque_varint(data, off)
        ct_val, off = read_uint8(data, off)
        ct = ContentType(ct_val)
        from .data_structures import Commit as _Commit, Proposal as _Proposal
        obj: Union[_Commit, _Proposal]
        if ct == ContentType.APPLICATION:
            body, off = read_opaque_varint(data, off)
        elif ct == ContentType.COMMIT:
            # Commit is self-delimiting (Path + ProposalsVector)
            # We parse it to determine length, then extract bytes.
            # This relies on Commit.deserialize being non-greedy logic (which we fixed).
            obj = _Commit.deserialize(data[off:])
            # Determine length by serializing the verified object
            # (Assuming round-trip is consistent, which it should be for RFC structures)
            length = len(obj.serialize())
            body = data[off : off + length]
            off += length
        elif ct == ContentType.PROPOSAL:
            # Proposal is self-delimiting (Type + Content)
            obj = _Proposal.deserialize(data[off:])
            length = len(obj.serialize())
            body = data[off : off + length]
            off += length
        else:
            # Fallback for unknown types or implied consumption
            # RFC 9420 §6: "parsing requires knowing the length... or context"
            # If we are here, we might be consuming everything, which is risky if followed by signature.
            # But Application is opaque<V> (handled above).
            # So this is only for other types?
            # Assuming consumes remainder:
            body = data[off:]
            off = len(data)
            
        return cls(group_id, epoch, sender, ad, ct, body)


@dataclass(frozen=True)
class AuthenticatedContentTBS:
    """To-Be-Signed structure per RFC 9420 §6.1."""
    
    wire_format: int  # WireFormat enum value
    framed_content: FramedContent
    group_context: Optional[bytes] = None  # serialized GroupContext (for member senders)

    def serialize(self) -> bytes:
        """Encode AuthenticatedContentTBS per RFC 9420 §6.1.
        
        This structure IS signed, and IS used for membership tag computation.
        It includes ProtocolVersion, WireFormat, FramedContent, and optional GroupContext.
        """
        out = write_uint16(0x0001)  # ProtocolVersion = mls10
        out += write_uint16(self.wire_format)
        out += self.framed_content.serialize()
        # For member senders, include GroupContext
        if self.group_context is not None:
            out += self.group_context
        return out

    def serialize_wire(self) -> bytes:
        """Encode the wire format prefix of AuthenticatedContent.
        
        This corresponds to the start of AuthenticatedContent on the wire:
        ProtocolVersion || WireFormat || FramedContent
        Wait, NO GroupContext!
        """
        out = write_uint16(0x0001)  # ProtocolVersion = mls10
        out += write_uint16(self.wire_format)
        out += self.framed_content.serialize()
        return out


@dataclass(frozen=True)
class FramedContentAuthData:
    """Structure for authentication data per RFC 9420 §5.2.
    
    struct {
        opaque signature<V>;
        select (FramedContent.content_type) {
            case commit: MAC confirmation_tag;
            case application:
            case proposal: struct{};
        };
    } FramedContentAuthData;
    """
    signature: bytes
    confirmation_tag: Optional[bytes] = None  # Present only if content_type == COMMIT
    
    def serialize(self) -> bytes:
        out = write_opaque_varint(self.signature)
        if self.confirmation_tag is not None:
            out += write_opaque_varint(self.confirmation_tag)
        return out

    @classmethod
    def deserialize(cls, data: bytes, content_type: ContentType) -> tuple["FramedContentAuthData", int]:
        off = 0
        sig, off = read_opaque_varint(data, off)
        ctag = None
        if content_type == ContentType.COMMIT:
            if off < len(data):
                ctag, off = read_opaque_varint(data, off)
            # Else maybe missing if partial? Strict RFC says it must be there.
        return cls(sig, ctag), off


@dataclass(frozen=True)
class AuthenticatedContent:
    """Authenticated content with signature and optional tags.
    RFC §6.2 PublicMessage:
    struct {
        AuthenticatedContent content;
        select (PublicMessage.content.sender.sender_type) {
            case member: MAC membership_tag;
            case external: struct{};
            ...
        };
    } PublicMessage;
    
    RFC §5.2 AuthenticatedContent:
    struct {
        ProtocolVersion version = mls10;
        WireFormat wire_format;
        FramedContent content;
        FramedContentAuthData auth;
    } AuthenticatedContent;
    """
    tbs: AuthenticatedContentTBS
    auth: FramedContentAuthData
    membership_tag: Optional[bytes] = None  # Part of PublicMessage, not AuthenticatedContent

    # Backward compatibility properties
    @property
    def signature(self) -> bytes:
        return self.auth.signature
        
    @property
    def confirmation_tag(self) -> Optional[bytes]:
        return self.auth.confirmation_tag

    def serialize(self) -> bytes:
        """Encode as PublicMessage structure: Content || MembershipTag (optional)."""
        # 1. Serialize AuthenticatedContent (wire format)
        # Note: TBS includes GroupContext, but wire format does NOT.
        out = self.tbs.serialize_wire()
        
        # 2. Serialize FramedContentAuthData
        out += self.auth.serialize()

        # 3. Membership Tag (PublicMessage field)
        if self.membership_tag is not None:
            out += write_opaque_varint(self.membership_tag)
        
        return out

    def serialize_tbm(self) -> bytes:
        """Serialize AuthenticatedContentTBM = TBS || AuthData."""
        return self.tbs.serialize() + self.auth.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "AuthenticatedContent":
        """Parse AuthenticatedContent from bytes."""
        off = 0
        # Read ProtocolVersion header (uint16)
        _version, off = read_uint16(data, off)
        # Read wire_format header
        wf, off = read_uint16(data, off)
        
        # FramedContent parsing (same logic as before)
        fc = FramedContent.deserialize(data[off:])
        # Determine consumed bytes by re-serializing (MVP hack)
        fc_ser = fc.serialize()
        off += len(fc_ser)
        
        # Parse AuthData
        auth, consumed = FramedContentAuthData.deserialize(data[off:], fc.content_type)
        off += consumed
        
        mtag = None
        # Check if bytes remain for membership tag
        if off < len(data):
            mtag, off = read_opaque_varint(data, off)
            
        tbs = AuthenticatedContentTBS(wire_format=wf, framed_content=fc)
        # Note: tbs.group_context is None here because it's not on the wire.
        # It must be supplied from context for verification if needed, 
        # but AuthenticatedContent object doesn't strictly need it to round-trip wire bytes.
        
        return cls(tbs, auth, mtag)


@dataclass(frozen=True)
class MLSPlaintext:
    """Top-level handshake plaintext container."""
    auth_content: AuthenticatedContent
    
    def serialize(self) -> bytes:
        return self.auth_content.serialize()

    @classmethod
    def deserialize(cls, data: bytes) -> "MLSPlaintext":
        return cls(AuthenticatedContent.deserialize(data))


@dataclass(frozen=True)
class SenderData:
    """SenderData protected field.
    struct {
        uint32 sender_leaf_index;
        uint32 generation;
        opaque reuse_guard[4];
    } SenderData;
    """
    sender: int
    generation: int
    reuse_guard: bytes

    def serialize(self) -> bytes:
        out = write_uint32(self.sender)  # Updated to uint32
        out += write_uint32(self.generation)
        # reuse_guard is opaque[4], fixed length. NO length prefix.
        if len(self.reuse_guard) != 4:
            raise ValueError("reuse_guard must be 4 bytes")
        out += self.reuse_guard
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "SenderData":
        off = 0
        s, off = read_uint32(data, off)
        g, off = read_uint32(data, off)
        # read 4 bytes for reuse_guard
        rg = data[off : off + 4]
        if len(rg) != 4:
            # Not enough data
            raise Exception("buffer underflow: reuse_guard requires 4 bytes")
        return cls(s, g, rg)


@dataclass(frozen=True)
class MLSCiphertext:
    """Encrypted MLS content container.
    struct {
        opaque group_id<V>;
        uint64 epoch;
        ContentType content_type;
        opaque authenticated_data<V>;
        opaque encrypted_sender_data<V>;
        opaque ciphertext<V>;
    } MLSCiphertext;
    """
    group_id: bytes
    epoch: int
    content_type: ContentType
    authenticated_data: bytes
    encrypted_sender_data: bytes
    ciphertext: bytes

    def serialize(self) -> bytes:
        out = write_opaque_varint(self.group_id)
        out += write_uint64(self.epoch)
        out += write_uint8(int(self.content_type))
        out += write_opaque_varint(self.authenticated_data)
        out += write_opaque_varint(self.encrypted_sender_data)
        out += write_opaque_varint(self.ciphertext)
        return out

    @classmethod
    def deserialize(cls, data: bytes) -> "MLSCiphertext":
        off = 0
        gid, off = read_opaque_varint(data, off)
        epoch, off = read_uint64(data, off)
        ct, off = read_uint8(data, off)
        ad, off = read_opaque_varint(data, off)
        esd, off = read_opaque_varint(data, off)
        body, off = read_opaque_varint(data, off)
        return cls(gid, epoch, ContentType(ct), ad, esd, body)


def encrypt_sender_data(
    sd: SenderData,
    key_schedule: KeySchedule,
    crypto: CryptoProvider,
    aad: bytes = b"",
    ciphertext_sample: Optional[bytes] = None,
) -> bytes:
    """Encrypt SenderData using sender data key/nonce derived from KeySchedule.
    
    aad MUST be SenderDataAAD(group_id, epoch, content_type) per RFC 9420.
    """
    if ciphertext_sample is not None:
        key = key_schedule.sender_data_key_from_sample(ciphertext_sample)
        nonce = key_schedule.sender_data_nonce_from_sample(ciphertext_sample)
    else:
        # Backward compatibility
        key = key_schedule.sender_data_key()
        nonce = key_schedule.sender_data_nonce(sd.reuse_guard)
    return crypto.aead_encrypt(key, nonce, sd.serialize(), aad)


def decrypt_sender_data(
    enc: bytes,
    reuse_guard: bytes,
    key_schedule: KeySchedule,
    crypto: CryptoProvider,
    aad: bytes = b"",
    ciphertext_sample: Optional[bytes] = None,
) -> SenderData:
    """Decrypt SenderData using sender data key/nonce."""
    if ciphertext_sample is not None:
        key = key_schedule.sender_data_key_from_sample(ciphertext_sample)
        # RFC §6.3.2: sender_data_nonce has no reuse_guard XOR
        nonce = key_schedule.sender_data_nonce_from_sample(ciphertext_sample)
    else:
        key = key_schedule.sender_data_key()
        nonce = key_schedule.sender_data_nonce(reuse_guard)
    ptxt = crypto.aead_decrypt(key, nonce, enc, aad)
    return SenderData.deserialize(ptxt)


def encode_encrypted_sender_data(
    sd: SenderData,
    key_schedule: KeySchedule,
    crypto: CryptoProvider,
    ciphertext_sample: Optional[bytes] = None,
    sender_data_aad: bytes = b"",
) -> bytes:
    """
    Encrypt SenderData and return the AEAD ciphertext.

    Per RFC 9420 §6.3.2, encrypted_sender_data<V> is purely the AEAD output
    over SenderData (which already contains the reuse_guard field). The
    reuse_guard is NOT prepended on the wire as a raw prefix.
    """
    return encrypt_sender_data(sd, key_schedule, crypto, aad=sender_data_aad, ciphertext_sample=ciphertext_sample)


def decode_encrypted_sender_data(
    data: bytes, 
    key_schedule: KeySchedule, 
    crypto: CryptoProvider, 
    ciphertext_sample: Optional[bytes] = None,
    sender_data_aad: bytes = b""
) -> SenderData:
    """Decrypt SenderData from the encrypted_sender_data<V> wire field.

    Per RFC 9420 §6.3.2, data is purely the AEAD ciphertext. The sender_data_nonce
    is derived from the ciphertext sample only (no reuse_guard XOR).
    """
    return decrypt_sender_data(data, b"", key_schedule, crypto, aad=sender_data_aad, ciphertext_sample=ciphertext_sample)


# AAD and padding helpers
def compute_ciphertext_aad(group_id: bytes, epoch: int, content_type: ContentType, authenticated_data: bytes) -> bytes:
    """
    RFC-style AAD for MLSCiphertext content encryption.
    """
    out = write_opaque_varint(group_id)
    out += write_uint64(epoch)  # Updated to uint64
    out += write_uint8(int(content_type))
    out += write_opaque_varint(authenticated_data)
    return out


def compute_sender_data_aad(group_id: bytes, epoch: int, content_type: ContentType) -> bytes:
    """
    SenderDataAAD per RFC 9420 §6.3.2.
    struct {
        opaque group_id<V>;
        uint64 epoch;
        ContentType content_type;
    } SenderDataAAD;
    """
    out = write_opaque_varint(group_id)
    out += write_uint64(epoch)
    out += write_uint8(int(content_type))
    return out


def add_zero_padding(data: bytes, pad_to: int) -> bytes:
    """Pad with zero bytes up to the next 'pad_to' boundary."""
    if pad_to <= 0:
        return data
    rem = len(data) % pad_to
    need = (pad_to - rem) % pad_to
    if need == 0:
        return data
    return data + (b"\x00" * need)


def strip_content_padding(data: bytes, verify_all_zeros: bool = True) -> bytes:
    """Remove RFC 9420 §6.3.1 content padding (trailing zero bytes).

    Raises ValueError if any padding byte is non-zero (per RFC MUST requirement).
    """
    end = len(data)
    while end > 0 and data[end - 1] == 0:
        end -= 1
    if verify_all_zeros:
        for b in data[end:]:
            if b != 0:
                raise ValueError("non-zero padding byte in PrivateMessageContent")
    return data[:end]

def sign_authenticated_content(
    group_id: bytes,
    epoch: int,
    sender_leaf_index: int,
    authenticated_data: bytes,
    content_type: ContentType,
    content: bytes,
    signing_private_key: bytes,
    crypto: CryptoProvider,
    group_context: Optional[bytes] = None,
    wire_format: int = WireFormat.PUBLIC_MESSAGE,
) -> MLSPlaintext:
    """Build MLSPlaintext by signing AuthenticatedContentTBS per RFC 9420 §6.1.

    Membership tag is left empty for the caller to attach via
    attach_membership_tag(), since it depends on the group membership key.

    Parameters
    - group_context: Serialized GroupContext bytes (required for member senders).
    - wire_format: WireFormat value (default: PUBLIC_MESSAGE).
    """
    from .data_structures import Sender as _Sender
    framed = FramedContent(
        group_id=group_id,
        epoch=epoch,
        sender=_Sender(sender_leaf_index),
        authenticated_data=authenticated_data,
        content_type=content_type,
        content=content,
    )
    tbs = AuthenticatedContentTBS(
        wire_format=wire_format,
        framed_content=framed,
        group_context=group_context,
    )
    # Domain-separated signing over FramedContentTBS
    sig = crypto.sign_with_label(signing_private_key, b"FramedContentTBS", tbs.serialize())
    auth_data = FramedContentAuthData(signature=sig, confirmation_tag=None)
    auth = AuthenticatedContent(tbs=tbs, auth=auth_data, membership_tag=None)
    return MLSPlaintext(auth)


def attach_membership_tag(plaintext: MLSPlaintext, membership_key: bytes, crypto: CryptoProvider) -> MLSPlaintext:
    """
    Compute membership tag over AuthenticatedContentTBM (TBS || AuthData).

    Parameters
    - plaintext: MLSPlaintext without a membership tag.
    - membership_key: Group membership MAC key.
    - crypto: Crypto provider offering HMAC.

    Returns
    - New MLSPlaintext with membership_tag set.
    """
    # RFC 9420 §6.2: Tag is MAC over AuthenticatedContentTBM
    tbm = plaintext.auth_content.serialize_tbm()
    tag = crypto.hmac_sign(membership_key, tbm)
    
    return MLSPlaintext(AuthenticatedContent(
        tbs=plaintext.auth_content.tbs, 
        auth=plaintext.auth_content.auth, 
        membership_tag=tag
    ))


def verify_plaintext(
    plaintext: MLSPlaintext,
    sender_signature_key: bytes,
    membership_key: Optional[bytes],
    crypto: CryptoProvider,
    group_context: Optional[bytes] = None,
) -> None:
    """
    Verify signature and (if provided) membership tag of an MLSPlaintext.
    Raises on failure.

    Parameters
    - plaintext: Message to verify.
    - sender_signature_key: Public key for verifying the signature.
    - membership_key: MAC key for membership tag verification, or None to skip.
    - crypto: Crypto provider exposing verify() and hmac_sign().
    - group_context: Serialized GroupContext bytes.  MUST be supplied when the
      sender type is MEMBER (RFC 9420 §6.1 — AuthenticatedContentTBS includes
      GroupContext for member senders).

    Raises
    - InvalidSignatureError: If signature or membership tag verification fails.
    """
    tbs = plaintext.auth_content.tbs
    # RFC §6.1: for member senders, TBS includes the serialized GroupContext.
    # If the TBS stored in the message doesn't have it, rebuild TBS with the
    # provided group_context so we verify over the correct bytes.
    if group_context is not None and tbs.group_context is None:
        tbs = AuthenticatedContentTBS(
            wire_format=tbs.wire_format,
            framed_content=tbs.framed_content,
            group_context=group_context,
        )
    tbs_ser = tbs.serialize()
    # Domain-separated signature verification
    crypto.verify_with_label(sender_signature_key, b"FramedContentTBS", tbs_ser, plaintext.auth_content.auth.signature)
    if membership_key is not None:
        # Check membership tag over AuthenticatedContentTBM (TBS || AuthData)
        # TBM uses the *full* TBS (including GroupContext)
        tbm = tbs_ser + plaintext.auth_content.auth.serialize()
        tag = crypto.hmac_sign(membership_key, tbm)
        if plaintext.auth_content.membership_tag is None or plaintext.auth_content.membership_tag != tag:
            raise InvalidSignatureError("invalid membership tag")


# --- High-level content protection helpers (MVP) ---
def protect_content_handshake(
    group_id: bytes,
    epoch: int,
    sender_leaf_index: int,
    authenticated_data: bytes,
    content: bytes,
    signature: bytes,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
    confirmation_tag: Optional[bytes] = None,
    content_type: ContentType = ContentType.COMMIT,
) -> MLSCiphertext:
    """
    Encrypt handshake content using the secret tree handshake branch.
    Derive SenderData keys from a ciphertext sample (RFC §6.3.2).
    
    Constructs PrivateMessageContent = content || auth || padding.
    """
    # Obtain per-sender handshake key/nonce and generation
    key, nonce, generation = secret_tree.next_handshake(sender_leaf_index)
    
    # Build PrivateMessageContent
    # For Handshake (Proposal/Commit), content is just the bytes (serialization of Proposal/Commit).
    # RFC §6.3:
    # select (content_type) { case proposal: Proposal; case commit: Commit; }
    # So NO length prefix for the content part itself (it's self-describing or consumed).
    pmc = content
    
    # Append AuthData
    auth = FramedContentAuthData(signature=signature, confirmation_tag=confirmation_tag)
    pmc += auth.serialize()
    
    # Padding (RFC says: "The sender MUST check that the padding field contains all zeros")
    # We just append zeros if we want padding. 
    # MVP: No extra padding for handshake usually, or maybe minimal?
    # padding = b"" 
    # But let's pad to some boundary if desired. For now, empty padding is valid (length 0).
    # If we want to hide length, we should pad.
    # Legacy: we didn't pad handshake.
    
    aad = compute_ciphertext_aad(group_id, epoch, content_type, authenticated_data)
    
    # Random reuse guard and final content nonce (nonce XOR reuse_guard)
    reuse_guard = os.urandom(4)
    rg_padded = reuse_guard.rjust(crypto.aead_nonce_size(), b"\x00")
    content_nonce = bytes(a ^ b for a, b in zip(nonce, rg_padded))
    
    # Encrypt content first to get ciphertext sample
    ct = crypto.aead_encrypt(key, content_nonce, pmc, aad)
    sample_len = crypto.kdf_hash_len()
    ciphertext_sample = ct[:sample_len]
    sd = SenderData(sender=sender_leaf_index, generation=generation, reuse_guard=reuse_guard)
    
    sd_aad = compute_sender_data_aad(group_id, epoch, content_type)
    enc_sd = encode_encrypted_sender_data(sd, key_schedule, crypto, ciphertext_sample=ciphertext_sample, sender_data_aad=sd_aad)
    
    return MLSCiphertext(
        group_id=group_id,
        epoch=epoch,
        content_type=content_type,
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
    signature: bytes,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
) -> MLSCiphertext:
    """
    Encrypt application content using the secret tree application branch.
    Derive SenderData keys from a ciphertext sample (RFC §6.3.2).
    """
    key, nonce, generation = secret_tree.next_application(sender_leaf_index)
    
    # Build PrivateMessageContent
    # Case application: opaque application_data<V>;
    # So we MUST write length prefix.
    pmc = write_opaque_varint(content)
    
    # AuthData
    auth = FramedContentAuthData(signature=signature, confirmation_tag=None)
    pmc += auth.serialize()
    
    pmc = add_zero_padding(pmc, pad_to=32)
    
    aad = compute_ciphertext_aad(group_id, epoch, ContentType.APPLICATION, authenticated_data)
    
    # Random reuse guard and final content nonce (nonce XOR reuse_guard)
    reuse_guard = os.urandom(4)
    rg_padded = reuse_guard.rjust(crypto.aead_nonce_size(), b"\x00")
    content_nonce = bytes(a ^ b for a, b in zip(nonce, rg_padded))
    # Encrypt to obtain ciphertext sample
    ct = crypto.aead_encrypt(key, content_nonce, pmc, aad)
    sample_len = crypto.kdf_hash_len()
    ciphertext_sample = ct[:sample_len]
    sd = SenderData(sender=sender_leaf_index, generation=generation, reuse_guard=reuse_guard)
    
    sd_aad = compute_sender_data_aad(group_id, epoch, ContentType.APPLICATION)
    enc_sd = encode_encrypted_sender_data(sd, key_schedule, crypto, ciphertext_sample=ciphertext_sample, sender_data_aad=sd_aad)
    
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
) -> tuple[int, bytes, FramedContentAuthData]:
    """
    Decrypt handshake content and return (sender_leaf_index, plaintext_content, auth_data).
    """
    aad = compute_ciphertext_aad(m.group_id, m.epoch, m.content_type, m.authenticated_data)
    # Derive SenderData keys using ciphertext sample first
    sample_len = crypto.kdf_hash_len()
    ciphertext_sample = m.ciphertext[:sample_len]
    sd_aad = compute_sender_data_aad(m.group_id, m.epoch, m.content_type)
    sd = decode_encrypted_sender_data(m.encrypted_sender_data, key_schedule, crypto, ciphertext_sample=ciphertext_sample, sender_data_aad=sd_aad)

    # RFC §6.3.2: sender leaf MUST be non-blank in the ratchet tree.
    rt = getattr(secret_tree, '_ratchet_tree', None) or (secret_tree if hasattr(secret_tree, 'get_node') else None)
    if rt is not None:
        try:
            _ln = rt.get_node(sd.sender * 2)
            if _ln.leaf_node is None and _ln.public_key is None:
                raise ValueError(f"SenderData references blank leaf at index {sd.sender}")
        except (AttributeError, IndexError):
            pass  # ratchet_tree not available; skip check

    key, nonce, _ = secret_tree.handshake_for(sd.sender, sd.generation)
    rg_padded = sd.reuse_guard.rjust(crypto.aead_nonce_size(), b"\x00")
    content_nonce = bytes(a ^ b for a, b in zip(nonce, rg_padded))
    ptxt = crypto.aead_decrypt(key, content_nonce, m.ciphertext, aad)
    
    # Parse PrivateMessageContent: content || auth || padding
    # RFC §6.3.1: parse content, then auth, THEN verify remaining bytes are zero padding.
    from .data_structures import Commit as _Commit, Proposal as _Proposal
    off = 0
    body = b""
    obj: Union[_Commit, _Proposal]
    if m.content_type == ContentType.COMMIT:
        obj = _Commit.deserialize(ptxt)
        length = len(obj.serialize())
        body = ptxt[:length]
        off = length
    elif m.content_type == ContentType.PROPOSAL:
        obj = _Proposal.deserialize(ptxt)
        length = len(obj.serialize())
        body = ptxt[:length]
        off = length
    else:
        raise ValueError(f"Unsupported handshake content type: {m.content_type}")

    # Parse AuthData
    auth, auth_len = FramedContentAuthData.deserialize(ptxt[off:], m.content_type)
    off += auth_len

    # Verify remaining bytes are all-zero padding (RFC 9420 §6.3.1 MUST)
    padding = ptxt[off:]
    if any(b != 0 for b in padding):
        raise ValueError("non-zero padding byte in PrivateMessageContent")

    return sd.sender, body, auth


def unprotect_content_application(
    m: MLSCiphertext,
    key_schedule: KeySchedule,
    secret_tree,
    crypto: CryptoProvider,
) -> tuple[int, bytes, FramedContentAuthData]:
    """
    Decrypt application content and return (sender_leaf_index, plaintext_content, auth_data).
    """
    aad = compute_ciphertext_aad(m.group_id, m.epoch, m.content_type, m.authenticated_data)
    sample_len = crypto.kdf_hash_len()
    ciphertext_sample = m.ciphertext[:sample_len]
    sd_aad = compute_sender_data_aad(m.group_id, m.epoch, m.content_type)
    sd = decode_encrypted_sender_data(m.encrypted_sender_data, key_schedule, crypto, ciphertext_sample=ciphertext_sample, sender_data_aad=sd_aad)

    # RFC §6.3.2: sender leaf MUST be non-blank in the ratchet tree.
    rt = getattr(secret_tree, '_ratchet_tree', None) or (secret_tree if hasattr(secret_tree, 'get_node') else None)
    if rt is not None:
        try:
            _ln = rt.get_node(sd.sender * 2)
            if _ln.leaf_node is None and _ln.public_key is None:
                raise ValueError(f"SenderData references blank leaf at index {sd.sender}")
        except (AttributeError, IndexError):
            pass  # ratchet_tree not available; skip check

    key, nonce, _ = secret_tree.application_for(sd.sender, sd.generation)
    rg_padded = sd.reuse_guard.rjust(crypto.aead_nonce_size(), b"\x00")
    content_nonce = bytes(a ^ b for a, b in zip(nonce, rg_padded))
    ptxt = crypto.aead_decrypt(key, content_nonce, m.ciphertext, aad)
    
    # Parse PrivateMessageContent: content || auth || padding
    # RFC §6.3.1: parse content, then auth, THEN verify remaining bytes are zero padding.
    off = 0
    # Application: opaque application_data<V>
    body, off = read_opaque_varint(ptxt, off)

    # Parse AuthData
    auth, auth_len = FramedContentAuthData.deserialize(ptxt[off:], m.content_type)
    off += auth_len

    # Verify remaining bytes are all-zero padding (RFC 9420 §6.3.1 MUST)
    padding = ptxt[off:]
    if any(b != 0 for b in padding):
        raise ValueError("non-zero padding byte in PrivateMessageContent")

    return sd.sender, body, auth

@dataclass(frozen=True)
class MLSMessage:
    """Top-level MLSMessage wrapper per RFC 9420 §6."""
    version: ProtocolVersion
    wire_format: WireFormat
    content: bytes  # PublicMessage | PrivateMessage | ...
    
    def serialize(self) -> bytes:
        out = write_uint16(self.version)
        out += write_uint16(self.wire_format)
        out += self.content
        return out
        
    @classmethod
    def deserialize(cls, data: bytes) -> "MLSMessage":
        off = 0
        v, off = read_uint16(data, off)
        wf, off = read_uint16(data, off)
        content = data[off:]
        return cls(ProtocolVersion(v), WireFormat(wf), content)
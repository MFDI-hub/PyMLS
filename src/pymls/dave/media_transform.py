from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from ..crypto.crypto_provider import CryptoProvider
from .ratchet import SenderKeyManager


def uleb128_encode(value: int) -> bytes:
    out = bytearray()
    v = int(value)
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(0x80 | b)
        else:
            out.append(b)
            break
    return bytes(out)


def uleb128_decode(buf: bytes, offset: int = 0) -> Tuple[int, int]:
    shift = 0
    result = 0
    while True:
        if offset >= len(buf):
            raise ValueError("ULEB128 decode overflow")
        b = buf[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 63:
            raise ValueError("ULEB128 too large")
    return result, offset


DAVE_MAGIC = b"DAVE"  # Placeholder magic marker for protocol frame check


@dataclass
class FrameEncryptor:
    crypto: CryptoProvider
    sender_keys: SenderKeyManager

    def encrypt_opus_frame(self, sender_user_id: int, frame: bytes) -> bytes:
        key, nonce = self.sender_keys.next_keys_for(sender_user_id)
        # cryptography AESGCM returns ciphertext||tag (tag=16 bytes)
        ciphertext_full = self.crypto.aead_encrypt(key, nonce, frame, b"")
        length_field = uleb128_encode(len(ciphertext_full))
        return DAVE_MAGIC + length_field + nonce + ciphertext_full


@dataclass
class FrameDecryptor:
    crypto: CryptoProvider

    def decrypt_opus_frame(self, key: bytes, nonce: bytes, payload: bytes) -> bytes:
        # payload = DAVE_MAGIC || len || nonce || ciphertext_full
        off = 0
        magic = payload[: len(DAVE_MAGIC)]
        if magic != DAVE_MAGIC:
            raise ValueError("invalid magic marker")
        off += len(DAVE_MAGIC)
        size, off = uleb128_decode(payload, off)
        rx_nonce = payload[off : off + len(nonce)]
        off += len(nonce)
        if rx_nonce != nonce:
            # Out-of-sync; caller should try with the correct ratchet
            raise ValueError("nonce mismatch")
        ciphertext_full = payload[off : off + size]
        return self.crypto.aead_decrypt(key, nonce, ciphertext_full, b"")


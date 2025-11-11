from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple

from ..protocol.key_schedule import KeySchedule
from ..crypto.crypto_provider import CryptoProvider


def _le64(x: int) -> bytes:
    return int(x).to_bytes(8, "little", signed=False)


def derive_sender_base_secret(
    key_schedule: KeySchedule,
    epoch: int,
    sender_user_id: int,
    out_len: int = 32,
) -> bytes:
    """
    DAVE: Per-sender base secret derived from MLS exporter, using
    little-endian user ID and little-endian epoch.
    """
    label = b"dave-sender-base-v1"
    context = _le64(sender_user_id) + _le64(epoch)
    return key_schedule.export(label, context, out_len)


@dataclass
class SenderRatchet:
    crypto: CryptoProvider
    base_secret: bytes
    key_len: int = 16  # AES-128-GCM
    nonce_len: int = 12
    label: bytes = b"dave-sender-gen-v1"
    generation: int = 0

    def derive_for_generation(self, generation: int) -> Tuple[bytes, bytes]:
        info = self.label + int(generation).to_bytes(8, "little")
        material = self.crypto.kdf_expand(self.base_secret, info, self.key_len + self.nonce_len)
        key = material[: self.key_len]
        nonce = material[self.key_len : self.key_len + self.nonce_len]
        return key, nonce

    def next_keys(self) -> Tuple[bytes, bytes]:
        key, nonce = self.derive_for_generation(self.generation)
        self.generation += 1
        return key, nonce


@dataclass
class SenderKeyManager:
    crypto: CryptoProvider
    ratchets: Dict[int, SenderRatchet] = field(default_factory=dict)  # user_id -> ratchet

    def ensure(self, user_id: int, base_secret: bytes) -> SenderRatchet:
        if user_id not in self.ratchets:
            self.ratchets[user_id] = SenderRatchet(self.crypto, base_secret)
        return self.ratchets[user_id]

    def next_keys_for(self, user_id: int) -> Tuple[bytes, bytes]:
        ratchet = self.ratchets[user_id]
        return ratchet.next_keys()


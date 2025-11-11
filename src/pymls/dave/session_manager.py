from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, Optional, Set, Tuple

from ..crypto.crypto_provider import CryptoProvider
from ..crypto.constants import DAVE_MLS_CIPHERSUITE
from ..protocol.key_packages import KeyPackage, LeafNode
from ..protocol.data_structures import Credential, Signature, Sender
from ..protocol.mls_group import MLSGroup
from .ratchet import SenderKeyManager, derive_sender_base_secret
from .codec import (
    pack_key_package,
    pack_proposals,
    pack_commit_or_welcome,
    pack_announce_commit,
    pack_welcome,
    unpack_proposals,
    unpack_commit_or_welcome,
    unpack_announce_commit,
    unpack_welcome,
    unpack_external_sender_package,
    OP_DAVE_MLS_COMMIT_WELCOME,
    OP_DAVE_MLS_PROPOSALS,
    OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION,
    OP_DAVE_MLS_WELCOME,
    OP_DAVE_MLS_EXTERNAL_SENDER_PACKAGE,
)


SendJSON = Callable[[dict], Awaitable[None]]
SendBinary = Callable[[bytes], Awaitable[None]]


@dataclass
class DaveSessionManager:
    crypto: CryptoProvider
    self_user_id: str
    send_json: SendJSON
    send_binary: SendBinary

    # Identity/crypto material
    signature_private_key: bytes
    signature_public_key: bytes
    kem_private_key: bytes
    kem_public_key: bytes

    # State
    sequence_number: int = 0
    protocol_version: Optional[str] = None
    mls_group: Optional[MLSGroup] = None
    recognized_user_ids: Set[str] = field(default_factory=set)
    user_id_to_leaf_index: Dict[str, int] = field(default_factory=dict)
    external_sender_package: Optional[bytes] = None
    sender_keys: SenderKeyManager = field(init=False)

    # Transition management
    current_transition_id: Optional[int] = None

    def _next_seq(self) -> int:
        self.sequence_number = (self.sequence_number + 1) & 0xFFFF
        return self.sequence_number

    def __post_init__(self) -> None:
        self.sender_keys = SenderKeyManager(self.crypto)

    # ---- MLS key package ----
    def build_key_package(self) -> KeyPackage:
        cred = Credential(identity=self.self_user_id.encode("utf-8"), public_key=self.signature_public_key)
        leaf = LeafNode(
            encryption_key=self.kem_public_key,
            signature_key=self.signature_public_key,
            credential=cred,
            capabilities=b"",
        )
        sig = self.crypto.sign(self.signature_private_key, leaf.serialize())
        return KeyPackage(leaf_node=leaf, signature=Signature(sig))

    # ---- Voice Gateway lifecycle handlers ----
    async def on_select_protocol_ack(self, version: str) -> None:
        self.protocol_version = version

    async def on_protocol_prepare_epoch(self, transition_id: int) -> None:
        """Initial epoch preparation → send KeyPackage."""
        self.current_transition_id = transition_id
        kp = self.build_key_package()
        payload = pack_key_package(self._next_seq(), kp)
        await self.send_binary(payload)

    async def on_mls_binary(self, packet: bytes) -> None:
        """Entry for binary DAVE MLS opcodes (27–30)."""
        # Dispatch based on opcode
        _, opcode, _ = self._peek_header(packet)
        if opcode == OP_DAVE_MLS_PROPOSALS:
            await self._handle_mls_proposals(packet)
        elif opcode == OP_DAVE_MLS_COMMIT_WELCOME:
            await self._handle_mls_commit_welcome(packet)
        elif opcode == OP_DAVE_MLS_ANNOUNCE_COMMIT_TRANSITION:
            await self._handle_mls_announce_commit(packet)
        elif opcode == OP_DAVE_MLS_WELCOME:
            await self._handle_mls_welcome(packet)
        elif opcode == OP_DAVE_MLS_EXTERNAL_SENDER_PACKAGE:
            await self._handle_external_sender(packet)
        else:
            # Ignore unsupported binary opcodes in this handler
            return

    @staticmethod
    def _peek_header(buf: bytes) -> Tuple[int, int, int]:
        from ..codec.tls import read_uint16, read_uint8

        seq, off = read_uint16(buf, 0)
        opcode, off = read_uint8(buf, off)
        return seq, opcode, off

    async def _handle_mls_proposals(self, packet: bytes) -> None:
        _seq, proposals, _sig, _ = unpack_proposals(packet, 0)
        from ..protocol.validations import validate_proposals_client_rules
        # Enforce DAVE Client Commit Validity (subset implemented)
        validate_proposals_client_rules(proposals)
        if not self.mls_group:
            # Group not yet created; keep proposals in pending (not persisted here)
            return
        for p in proposals:
            # In a complete implementation, validate against recognized users and roster
            # using commit validity checks. For now, accept and queue proposals.
            # Sender mapping unknown here; use a placeholder sender index 0.
            self.mls_group.process_proposal(
                message=self._public_message_from_proposal(p),
                sender=Sender(0),
            )

    def _public_message_from_proposal(self, p: Proposal) -> "PublicMessage":
        from ..protocol.messages import PublicMessage
        content = p.serialize()
        sig = self.crypto.sign(self.signature_private_key, content)
        return PublicMessage(content, Signature(sig))

    async def _handle_mls_commit_welcome(self, packet: bytes) -> None:
        _seq, transition_id, kind, payload, _ = unpack_commit_or_welcome(packet, 0)
        self.current_transition_id = transition_id
        if kind == 0:
            # Commit path
            commit, _sig = payload  # type: ignore[assignment]
            if self.mls_group is None:
                # Create group context minimally if missing
                kp = self.build_key_package()
                self.mls_group = MLSGroup.create(group_id=b"dave", key_package=kp, crypto_provider=self.crypto)
            # Process commit (simplified; real flow would verify and apply to tree)
            # Not implemented in MLSGroup currently; placeholder for completeness
            # self.mls_group.process_commit(commit)
        else:
            # Welcome path
            welcome = payload  # type: ignore[assignment]
            kp = self.build_key_package()
            self.mls_group = MLSGroup.from_welcome(welcome, kp, self.crypto)
            self._refresh_sender_ratchets()

    async def _handle_mls_announce_commit(self, packet: bytes) -> None:
        _seq, transition_id, commit, _sig, _ = unpack_announce_commit(packet, 0)
        self.current_transition_id = transition_id
        if self.mls_group:
            # Apply commit to move to next epoch (not fully implemented in MLSGroup)
            # self.mls_group.process_commit_broadcast(commit)
            self._refresh_sender_ratchets()

    async def _handle_mls_welcome(self, packet: bytes) -> None:
        _seq, transition_id, welcome, _ = unpack_welcome(packet, 0)
        self.current_transition_id = transition_id
        kp = self.build_key_package()
        self.mls_group = MLSGroup.from_welcome(welcome, kp, self.crypto)
        self._refresh_sender_ratchets()

    # ---- Roster mapping helpers ----
    def set_recognized_users(self, user_ids: Set[str]) -> None:
        self.recognized_user_ids = set(user_ids)

    def set_external_sender(self, package_bytes: bytes) -> None:
        self.external_sender_package = package_bytes

    # ---- Utilities for callers ----
    def get_leaf_index_for_user(self, user_id: str) -> Optional[int]:
        return self.user_id_to_leaf_index.get(user_id)

    def set_leaf_index_for_user(self, user_id: str, leaf_index: int) -> None:
        self.user_id_to_leaf_index[user_id] = leaf_index

    async def _handle_external_sender(self, packet: bytes) -> None:
        _seq, package, _ = unpack_external_sender_package(packet, 0)
        self.set_external_sender(package)

    # ---- Sender key derivation ----
    def _refresh_sender_ratchets(self) -> None:
        if not self.mls_group or not getattr(self.mls_group, "_key_schedule", None):
            return
        key_schedule = self.mls_group._key_schedule  # type: ignore[attr-defined]
        group_ctx = self.mls_group._group_context  # type: ignore[attr-defined]
        if key_schedule is None or group_ctx is None:
            return
        epoch = group_ctx.epoch
        for uid in {self.self_user_id, *self.recognized_user_ids}:
            try:
                uid_int = int(uid)
            except Exception:
                # If non-numeric, derive on a best-effort basis using hash
                uid_int = int.from_bytes(uid.encode("utf-8")[:8].ljust(8, b"\x00"), "little")
            base = derive_sender_base_secret(key_schedule, epoch, uid_int)
            self.sender_keys.ensure(uid_int, base)


from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import OrderedDict
from hashlib import sha256
from typing import Optional

from .session import MLSGroupSession
from ..interop.wire import decode_handshake


@dataclass
class MLSAppPolicy:
    """High-level application policy for RFC 9420 operational controls."""

    update_interval_seconds: Optional[int] = None
    max_idle_before_update: Optional[int] = None
    max_resumption_epochs: int = 8

    secret_tree_window_size: int = 128
    max_generation_gap: int = 1000
    aead_limit_bytes: Optional[int] = None

    conflict_resolution_strategy: str = "first_seen"
    enforce_epoch_lock: bool = True

    x509_mode: str = "warn_only"
    trust_roots: list[bytes] = field(default_factory=list)
    x509_policy: object | None = None

    @classmethod
    def recommended(cls) -> "MLSAppPolicy":
        """Balanced defaults suitable for most applications."""
        return cls(
            update_interval_seconds=24 * 60 * 60,
            max_idle_before_update=24 * 60 * 60,
            max_resumption_epochs=8,
            secret_tree_window_size=128,
            max_generation_gap=1000,
            aead_limit_bytes=32 * 1024 * 1024,
            conflict_resolution_strategy="deterministic_hash",
            enforce_epoch_lock=True,
            x509_mode="warn_only",
        )

    def as_runtime_dict(self) -> dict[str, int | None]:
        return {
            "secret_tree_window_size": int(self.secret_tree_window_size),
            "max_generation_gap": int(self.max_generation_gap),
            "aead_limit_bytes": self.aead_limit_bytes,
            "max_resumption_epochs": int(self.max_resumption_epochs),
            "update_interval_seconds": self.update_interval_seconds,
            "max_idle_before_update": self.max_idle_before_update,
        }


@dataclass
class CommitIngestResult:
    status: str
    applied: bool
    epoch: int
    reason: str = ""


class MLSOrchestrator:
    """Policy-aware helper that wraps commit sequencing and retention decisions."""

    def __init__(self, session: MLSGroupSession, policy: MLSAppPolicy):
        self._session = session
        self._policy = policy
        self._last_activity_at = datetime.now(timezone.utc)
        self._last_self_update_at = self._last_activity_at
        self._pending_commit_bytes: dict[int, bytes] = {}
        self._resumption_psks: "OrderedDict[int, bytes]" = OrderedDict()

    @property
    def policy(self) -> MLSAppPolicy:
        return self._policy

    def note_activity(self) -> None:
        self._last_activity_at = datetime.now(timezone.utc)

    def should_rotate_now(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        if self._policy.update_interval_seconds is not None:
            elapsed = (now - self._last_self_update_at).total_seconds()
            if elapsed >= max(1, int(self._policy.update_interval_seconds)):
                return True
        if self._policy.max_idle_before_update is not None:
            idle = (now - self._last_activity_at).total_seconds()
            if idle >= max(1, int(self._policy.max_idle_before_update)):
                return True
        return False

    def record_self_update(self, now: datetime | None = None) -> None:
        ts = now or datetime.now(timezone.utc)
        self._last_self_update_at = ts
        self._last_activity_at = ts

    def record_resumption_psk(self, epoch: int, psk: bytes) -> None:
        self._resumption_psks[int(epoch)] = psk
        self._resumption_psks.move_to_end(int(epoch))
        while len(self._resumption_psks) > max(0, int(self._policy.max_resumption_epochs)):
            self._resumption_psks.popitem(last=False)

    def list_resumption_psks(self) -> list[tuple[int, bytes]]:
        return list(self._resumption_psks.items())

    def _pick_commit(self, epoch: int, incoming_commit_bytes: bytes, sender_leaf_index: int) -> bytes:
        existing = self._pending_commit_bytes.get(epoch)
        if existing is None:
            return incoming_commit_bytes
        strategy = (self._policy.conflict_resolution_strategy or "first_seen").strip().lower()
        if strategy == "first_seen":
            return existing
        if strategy == "highest_sender":
            existing_sender = self._extract_sender_leaf(existing)
            return incoming_commit_bytes if sender_leaf_index >= existing_sender else existing
        if strategy == "deterministic_hash":
            existing_h = sha256(existing).digest()
            incoming_h = sha256(incoming_commit_bytes).digest()
            return incoming_commit_bytes if incoming_h < existing_h else existing
        return existing

    @staticmethod
    def _extract_sender_leaf(commit_bytes: bytes) -> int:
        try:
            pt = decode_handshake(commit_bytes)
            return int(pt.auth_content.tbs.framed_content.sender.sender)
        except Exception:
            return -1

    def ingest_commit(self, commit_bytes: bytes, sender_leaf_index: int) -> CommitIngestResult:
        try:
            pt = decode_handshake(commit_bytes)
            msg_epoch = int(pt.auth_content.tbs.framed_content.epoch)
        except Exception as exc:
            return CommitIngestResult(
                status="rejected",
                applied=False,
                epoch=self._session.epoch,
                reason=f"invalid_commit_encoding: {exc}",
            )

        current_epoch = int(self._session.epoch)
        if msg_epoch < current_epoch:
            return CommitIngestResult(
                status="stale",
                applied=False,
                epoch=msg_epoch,
                reason="commit epoch is behind local epoch",
            )
        if self._policy.enforce_epoch_lock and msg_epoch > current_epoch:
            return CommitIngestResult(
                status="deferred",
                applied=False,
                epoch=msg_epoch,
                reason="commit epoch is ahead of local epoch",
            )

        chosen = self._pick_commit(msg_epoch, commit_bytes, sender_leaf_index)
        self._pending_commit_bytes[msg_epoch] = chosen
        if chosen != commit_bytes:
            return CommitIngestResult(
                status="conflict",
                applied=False,
                epoch=msg_epoch,
                reason="commit not selected by conflict strategy",
            )

        self._session.apply_commit(chosen, sender_leaf_index=sender_leaf_index)
        self._pending_commit_bytes.pop(msg_epoch, None)
        self.note_activity()
        return CommitIngestResult(status="accepted", applied=True, epoch=msg_epoch)

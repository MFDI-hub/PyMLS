"""Async SQLite storage backend implementing StorageProviderProtocol.

Uses aiosqlite for atomic merge_group_state within a single transaction.
Schema: key_packages by ref; proposals by group_id + sequence; group_state one row per group_id.

Threat model
------------
``tree_snapshot`` holds private HPKE keys and ``state_payload`` holds epoch
secrets. This backend stores those blobs in the database file.

- Without ``at_rest_key``, the blobs are plaintext. Anyone who can read the
  file can impersonate the member and decrypt group traffic.
- Pass a 32-byte ``at_rest_key`` to encrypt every blob with AES-256-GCM
  before it is written. The key is not stored in the database. Losing the
  key makes the file unreadable. A wrong key fails closed.
- On platforms that honor POSIX modes, the file is created mode ``0o600``
  (owner read/write). Windows does not apply that restriction; restrict the
  file ACL yourself there.
- Key packages and proposals are stored with their TLS serialization.
  ``pickle`` is not used, and records that are not this format are rejected.
"""
from __future__ import annotations

import os
import sqlite3
import struct
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from ...providers.storage import GroupEpochState

try:
    import aiosqlite
except ImportError as e:
    raise ImportError(
        "aiosqlite is required for SQLiteStorageProvider. Install with: pip install aiosqlite"
    ) from e


_SCHEMA = """
CREATE TABLE IF NOT EXISTS key_packages (
    ref BLOB PRIMARY KEY,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS proposals (
    group_id BLOB NOT NULL,
    seq INTEGER NOT NULL,
    data BLOB NOT NULL,
    PRIMARY KEY (group_id, seq)
);

CREATE TABLE IF NOT EXISTS group_state (
    group_id BLOB PRIMARY KEY,
    epoch INTEGER NOT NULL,
    tree_snapshot BLOB NOT NULL,
    group_context BLOB NOT NULL,
    state_payload BLOB NOT NULL
);
"""

_PLAIN_MAGIC = b"MLS1"
_ENC_MAGIC = b"ENC1"
_KIND_BYTES = 1
_KIND_KEY_PACKAGE = 2
_KIND_PROPOSAL = 3
_AAD_PREFIX = b"rfc9420-sqlite-v1|"


def _pack_object(obj: Any) -> bytes:
    """Encode a key package, proposal, or raw bytes. Rejects every other type."""
    if isinstance(obj, memoryview):
        obj = obj.tobytes()
    if isinstance(obj, bytearray):
        obj = bytes(obj)
    if isinstance(obj, bytes):
        kind = _KIND_BYTES
        payload = obj
    else:
        from ...messages.data_structures import Proposal
        from ...messages.key_packages import KeyPackage

        if isinstance(obj, KeyPackage):
            kind = _KIND_KEY_PACKAGE
            payload = obj.serialize()
        elif isinstance(obj, Proposal):
            kind = _KIND_PROPOSAL
            payload = obj.serialize()
        else:
            raise TypeError(
                "SQLite storage accepts bytes, KeyPackage, or Proposal; "
                "pickle is not used"
            )
    if len(payload) > 0xFFFFFFFF:
        raise ValueError("storage object is too large")
    return bytes([kind]) + struct.pack("!I", len(payload)) + payload


def _unpack_object(blob: bytes) -> Any:
    if len(blob) < 5:
        raise ValueError("truncated storage record")
    kind = blob[0]
    (length,) = struct.unpack("!I", blob[1:5])
    payload = blob[5:]
    if len(payload) != length:
        raise ValueError("storage record length mismatch")
    if kind == _KIND_BYTES:
        return payload
    if kind == _KIND_KEY_PACKAGE:
        from ...messages.key_packages import KeyPackage

        return KeyPackage.deserialize(payload)
    if kind == _KIND_PROPOSAL:
        from ...messages.data_structures import Proposal

        return Proposal.deserialize(payload)
    raise ValueError(f"unknown storage record kind {kind}")


class SQLiteStorageProvider:
    """Async SQLite implementation of StorageProviderProtocol.

    merge_group_state is atomic: executed in a single transaction with
    BEGIN IMMEDIATE; UPDATE/INSERT group_state; COMMIT (or rollback on error).

    See the module docstring for what is and is not protected on disk.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        init_schema: bool = True,
        at_rest_key: bytes | None = None,
    ) -> None:
        """Initialize the provider with a database file path.

        Parameters:
            path: Path to the SQLite database file (created if missing).
            init_schema: If True (default), create tables on first use.
            at_rest_key: Optional 32-byte AES-256-GCM key. When set, every
                stored blob is encrypted. When omitted, blobs are plaintext.
        """
        self._path = str(Path(path).resolve())
        self._init_schema = init_schema
        if at_rest_key is None:
            self._at_rest_key: bytes | None = None
        else:
            key = bytes(at_rest_key)
            if len(key) != 32:
                raise ValueError("at_rest_key must be 32 bytes")
            self._at_rest_key = key

    def _restrict_file_permissions(self) -> None:
        """Best-effort owner-only mode. No-op when the platform rejects chmod."""
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            return

    def _seal(self, plaintext: bytes, column: str) -> bytes:
        if self._at_rest_key is None:
            return _PLAIN_MAGIC + plaintext
        nonce = os.urandom(12)
        aad = _AAD_PREFIX + column.encode("ascii")
        ciphertext = AESGCM(self._at_rest_key).encrypt(nonce, plaintext, aad)
        return _ENC_MAGIC + nonce + ciphertext

    def _open(self, stored: bytes, column: str) -> bytes:
        if stored.startswith(_ENC_MAGIC):
            if self._at_rest_key is None:
                raise ValueError("database blob is encrypted; construct the provider with at_rest_key")
            if len(stored) < 4 + 12 + 16:
                raise ValueError("truncated encrypted storage blob")
            nonce = stored[4:16]
            ciphertext = stored[16:]
            aad = _AAD_PREFIX + column.encode("ascii")
            try:
                return AESGCM(self._at_rest_key).decrypt(nonce, ciphertext, aad)
            except InvalidTag as exc:
                raise ValueError("storage decryption failed") from exc
        if stored.startswith(_PLAIN_MAGIC):
            if self._at_rest_key is not None:
                raise ValueError(
                    "plaintext blob in a database opened with at_rest_key"
                )
            return stored[4:]
        raise ValueError("unrecognized storage blob; pickle records are not accepted")

    async def _ensure_schema(self, db: aiosqlite.Connection) -> None:
        if self._init_schema:
            await db.executescript(_SCHEMA)
            await db.commit()
        self._restrict_file_permissions()

    async def save_key_package(self, ref: bytes, key_package: Any) -> None:
        data = self._seal(_pack_object(key_package), "key_packages")
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            await db.execute(
                "INSERT OR REPLACE INTO key_packages (ref, data) VALUES (?, ?)",
                (ref, data),
            )
            await db.commit()

    async def get_key_package(self, ref: bytes) -> Any | None:
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            db.row_factory = sqlite3.Row
            async with db.execute(
                "SELECT data FROM key_packages WHERE ref = ?", (ref,)
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            return None
        return _unpack_object(self._open(row["data"], "key_packages"))

    async def append_proposal(self, group_id: bytes, proposal: Any) -> None:
        data = self._seal(_pack_object(proposal), "proposals")
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            async with db.execute(
                "SELECT COALESCE(MAX(seq), -1) + 1 AS next FROM proposals WHERE group_id = ?",
                (group_id,),
            ) as cur:
                row = await cur.fetchone()
                if row is None:
                    raise RuntimeError("failed to compute next proposal sequence")
                next_seq = row[0]
            await db.execute(
                "INSERT INTO proposals (group_id, seq, data) VALUES (?, ?, ?)",
                (group_id, next_seq, data),
            )
            await db.commit()

    async def get_proposals(self, group_id: bytes) -> list[Any]:
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            async with db.execute(
                "SELECT data FROM proposals WHERE group_id = ? ORDER BY seq",
                (group_id,),
            ) as cur:
                rows = await cur.fetchall()
        return [_unpack_object(self._open(row[0], "proposals")) for row in rows]

    async def clear_proposals(self, group_id: bytes) -> None:
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            await db.execute("DELETE FROM proposals WHERE group_id = ?", (group_id,))
            await db.commit()

    async def merge_group_state(
        self, group_id: bytes, new_state: GroupEpochState
    ) -> None:
        """Atomically replace the group's persisted state with the new epoch state."""
        tree_snapshot = self._seal(new_state.tree_snapshot, "tree_snapshot")
        group_context = self._seal(new_state.group_context, "group_context")
        state_payload = self._seal(new_state.state_payload, "state_payload")
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            await db.execute("BEGIN IMMEDIATE")
            try:
                await db.execute(
                    """INSERT INTO group_state (group_id, epoch, tree_snapshot, group_context, state_payload)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT (group_id) DO UPDATE SET
                         epoch = excluded.epoch,
                         tree_snapshot = excluded.tree_snapshot,
                         group_context = excluded.group_context,
                         state_payload = excluded.state_payload""",
                    (
                        new_state.group_id,
                        new_state.epoch,
                        tree_snapshot,
                        group_context,
                        state_payload,
                    ),
                )
                await db.commit()
            except Exception:
                await db.rollback()
                raise

    async def get_group_state(self, group_id: bytes) -> GroupEpochState | None:
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            db.row_factory = sqlite3.Row
            async with db.execute(
                "SELECT epoch, tree_snapshot, group_context, state_payload FROM group_state WHERE group_id = ?",
                (group_id,),
            ) as cur:
                row = await cur.fetchone()
        if row is None:
            return None
        return GroupEpochState(
            group_id=group_id,
            epoch=row["epoch"],
            tree_snapshot=self._open(row["tree_snapshot"], "tree_snapshot"),
            group_context=self._open(row["group_context"], "group_context"),
            state_payload=self._open(row["state_payload"], "state_payload"),
        )

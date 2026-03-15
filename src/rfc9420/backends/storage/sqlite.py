"""Async SQLite storage backend implementing StorageProviderProtocol.

Uses aiosqlite for atomic merge_group_state within a single transaction.
Schema: key_packages by ref; proposals by group_id + sequence; group_state one row per group_id.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

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


class SQLiteStorageProvider:
    """Async SQLite implementation of StorageProviderProtocol.

    merge_group_state is atomic: executed in a single transaction with
    BEGIN IMMEDIATE; UPDATE/INSERT group_state; COMMIT (or rollback on error).
    """

    def __init__(self, path: str | Path, *, init_schema: bool = True) -> None:
        """Initialize the provider with a database file path.

        Parameters:
            path: Path to the SQLite database file (created if missing).
            init_schema: If True (default), create tables on first use.
        """
        self._path = str(Path(path).resolve())
        self._init_schema = init_schema

    async def _ensure_schema(self, db: aiosqlite.Connection) -> None:
        if not self._init_schema:
            return
        await db.executescript(_SCHEMA)
        await db.commit()

    async def save_key_package(self, ref: bytes, key_package: Any) -> None:
        # Serialize to bytes for storage; protocol types may need pickle or custom serialization.
        import pickle
        data = pickle.dumps(key_package)
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
        import pickle
        return pickle.loads(row["data"])

    async def append_proposal(self, group_id: bytes, proposal: Any) -> None:
        import pickle
        data = pickle.dumps(proposal)
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
        import pickle
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            async with db.execute(
                "SELECT data FROM proposals WHERE group_id = ? ORDER BY seq",
                (group_id,),
            ) as cur:
                rows = await cur.fetchall()
        return [pickle.loads(row[0]) for row in rows]

    async def clear_proposals(self, group_id: bytes) -> None:
        async with aiosqlite.connect(self._path) as db:
            await self._ensure_schema(db)
            await db.execute("DELETE FROM proposals WHERE group_id = ?", (group_id,))
            await db.commit()

    async def merge_group_state(
        self, group_id: bytes, new_state: GroupEpochState
    ) -> None:
        """Atomically replace the group's persisted state with the new epoch state."""
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
                        new_state.tree_snapshot,
                        new_state.group_context,
                        new_state.state_payload,
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
            tree_snapshot=row["tree_snapshot"],
            group_context=row["group_context"],
            state_payload=row["state_payload"],
        )

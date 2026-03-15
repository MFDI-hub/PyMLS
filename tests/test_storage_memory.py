"""Tests for in-memory async storage backend and atomic merge_group_state."""
from __future__ import annotations

import asyncio
import pytest

from rfc9420.providers.storage import GroupEpochState
from rfc9420.backends.storage.memory import MemoryStorageProvider


@pytest.fixture
def storage():
    return MemoryStorageProvider()


def _run(coro):
    return asyncio.run(coro)


def test_key_package_roundtrip(storage):
    async def _():
        ref = b"kp_ref_1"
        kp = {"init_key": b"fake_pk", "leaf_node": b"fake_leaf"}
        await storage.save_key_package(ref, kp)
        got = await storage.get_key_package(ref)
        assert got is kp
        assert await storage.get_key_package(b"nonexistent") is None

    _run(_())


def test_proposals_append_and_get(storage):
    async def _():
        gid = b"group1"
        p1 = {"type": "add", "key_package": b"kp1"}
        p2 = {"type": "remove", "index": 1}
        await storage.append_proposal(gid, p1)
        await storage.append_proposal(gid, p2)
        proposals = await storage.get_proposals(gid)
        assert len(proposals) == 2
        assert proposals[0] is p1 and proposals[1] is p2
        assert await storage.get_proposals(b"other_group") == []

    _run(_())


def test_clear_proposals(storage):
    async def _():
        gid = b"group1"
        await storage.append_proposal(gid, {"type": "add"})
        await storage.clear_proposals(gid)
        assert await storage.get_proposals(gid) == []

    _run(_())


def test_merge_group_state_atomic(storage):
    async def _():
        gid = b"group1"
        state1 = GroupEpochState(
            group_id=gid,
            epoch=1,
            tree_snapshot=b"tree_v1",
            group_context=b"gc_v1",
            state_payload=b"payload_v1",
        )
        await storage.merge_group_state(gid, state1)
        got = await storage.get_group_state(gid)
        assert got is not None
        assert got.epoch == 1
        assert got.tree_snapshot == b"tree_v1"
        assert got.group_context == b"gc_v1"
        assert got.state_payload == b"payload_v1"

    _run(_())


def test_merge_group_state_replacement(storage):
    async def _():
        gid = b"group1"
        await storage.merge_group_state(
            gid,
            GroupEpochState(
                group_id=gid,
                epoch=0,
                tree_snapshot=b"tree0",
                group_context=b"gc0",
                state_payload=b"p0",
            ),
        )
        await storage.merge_group_state(
            gid,
            GroupEpochState(
                group_id=gid,
                epoch=1,
                tree_snapshot=b"tree1",
                group_context=b"gc1",
                state_payload=b"p1",
            ),
        )
        got = await storage.get_group_state(gid)
        assert got is not None
        assert got.epoch == 1
        assert got.tree_snapshot == b"tree1"
        assert got.state_payload == b"p1"

    _run(_())


def test_get_group_state_none(storage):
    async def _():
        assert await storage.get_group_state(b"no_such_group") is None

    _run(_())

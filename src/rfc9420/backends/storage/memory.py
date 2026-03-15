"""In-memory async storage backend for testing and ephemeral use.

All state is held in process memory. merge_group_state is atomic (single dict update).
"""
from __future__ import annotations

from typing import Any

from ...providers.storage import GroupEpochState


class MemoryStorageProvider:
    """Async in-memory implementation of StorageProviderProtocol.

    Key packages, proposals, and group state are stored in dicts/lists.
    merge_group_state replaces the group's state in one step (atomic).
    """

    def __init__(self) -> None:
        """Initialize empty in-memory storage."""
        self._key_packages: dict[bytes, Any] = {}
        self._proposals: dict[bytes, list[Any]] = {}
        self._group_state: dict[bytes, GroupEpochState] = {}

    async def save_key_package(self, ref: bytes, key_package: Any) -> None:
        """Store a key package by its reference (hash).

        Parameters
        ----------
        ref : bytes
            Key package reference (hash).
        key_package : Any
            Key package to store.
        """
        self._key_packages[ref] = key_package

    async def get_key_package(self, ref: bytes) -> Any | None:
        """Retrieve a key package by reference, or None if not found.

        Parameters
        ----------
        ref : bytes
            Key package reference (hash).

        Returns
        -------
        Any or None
            Key package or None if not found.
        """
        return self._key_packages.get(ref)

    async def append_proposal(self, group_id: bytes, proposal: Any) -> None:
        """Append a proposal to the group's proposal queue.

        Parameters
        ----------
        group_id : bytes
            Group identifier.
        proposal : Any
            Proposal to append.
        """
        if group_id not in self._proposals:
            self._proposals[group_id] = []
        self._proposals[group_id].append(proposal)

    async def get_proposals(self, group_id: bytes) -> list[Any]:
        """Return all pending proposals for the group (order preserved).

        Parameters
        ----------
        group_id : bytes
            Group identifier.

        Returns
        -------
        list[Any]
            Pending proposals in order.
        """
        return list(self._proposals.get(group_id, []))

    async def clear_proposals(self, group_id: bytes) -> None:
        """Remove all pending proposals for the group (e.g. after merge).

        Parameters
        ----------
        group_id : bytes
            Group identifier.
        """
        self._proposals[group_id] = []

    async def merge_group_state(
        self, group_id: bytes, new_state: GroupEpochState
    ) -> None:
        """Atomically replace the group's persisted state with the new epoch state.

        Parameters
        ----------
        group_id : bytes
            Group identifier.
        new_state : GroupEpochState
            New epoch state to persist.
        """
        self._group_state[group_id] = new_state

    async def get_group_state(self, group_id: bytes) -> GroupEpochState | None:
        """Load the latest persisted epoch state for the group, or None.

        Parameters
        ----------
        group_id : bytes
            Group identifier.

        Returns
        -------
        GroupEpochState or None
            Latest epoch state or None if not found.
        """
        return self._group_state.get(group_id)

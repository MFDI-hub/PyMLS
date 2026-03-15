"""Protocol for MLS state persistence and atomic epoch commits.

Storage backends implement key package directory, proposal queue, and
atomic merge of group epoch state. All methods are async for native
integration with async databases.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable, Any

# Type aliases for storage payloads; concrete types from protocol layer
# are used at runtime but not imported here to avoid circular deps.
KeyPackageT = Any
ProposalT = Any


@dataclass(frozen=True)
class GroupEpochState:
    """Serializable snapshot of group state for one epoch after a commit.

    Used by StorageProvider.merge_group_state to persist atomically.
    The group layer is responsible for packing and unpacking these blobs.

    Parameters
    ----------
    group_id : bytes
        Group identifier.
    epoch : int
        Epoch number.
    tree_snapshot : bytes
        Serialized ratchet tree snapshot.
    group_context : bytes
        Serialized GroupContext for this epoch.
    state_payload : bytes
        Opaque payload: key schedule secrets, secret tree state, proposal cache, etc.
    """

    group_id: bytes
    epoch: int
    tree_snapshot: bytes
    group_context: bytes
    """Serialized GroupContext for this epoch."""
    state_payload: bytes
    """Opaque payload: key schedule secrets, secret tree state, proposal cache, etc."""


@runtime_checkable
class StorageProviderProtocol(Protocol):
    """Async interface for saving and loading MLS state.

    merge_group_state MUST be atomic: either the full new state is persisted
    or none of it. Partial writes would break cryptographic synchronization.
    """

    async def save_key_package(self, ref: bytes, key_package: KeyPackageT) -> None:
        """Store a key package by its reference (hash).

        Parameters
        ----------
        ref : bytes
            Key package reference (hash).
        key_package : KeyPackageT
            Key package to store.
        """
        ...

    async def get_key_package(self, ref: bytes) -> KeyPackageT | None:
        """Retrieve a key package by reference, or None if not found.

        Parameters
        ----------
        ref : bytes
            Key package reference (hash).

        Returns
        -------
        KeyPackageT or None
            Key package or None if not found.
        """
        ...

    async def append_proposal(self, group_id: bytes, proposal: ProposalT) -> None:
        """Append a proposal to the group's proposal queue.

        Parameters
        ----------
        group_id : bytes
            Group identifier.
        proposal : ProposalT
            Proposal to append.
        """
        ...

    async def get_proposals(self, group_id: bytes) -> list[ProposalT]:
        """Return all pending proposals for the group (order preserved).

        Parameters
        ----------
        group_id : bytes
            Group identifier.

        Returns
        -------
        list[ProposalT]
            Pending proposals in order.
        """
        ...

    async def clear_proposals(self, group_id: bytes) -> None:
        """Remove all pending proposals for the group (e.g. after merge).

        Parameters
        ----------
        group_id : bytes
            Group identifier.
        """
        ...

    async def merge_group_state(
        self, group_id: bytes, new_state: GroupEpochState
    ) -> None:
        """Atomically replace the group's persisted state with the new epoch state.

        Must persist tree_snapshot, group_context, and state_payload together.
        Raise on failure; no partial update.

        Parameters
        ----------
        group_id : bytes
            Group identifier.
        new_state : GroupEpochState
            New epoch state to persist.
        """
        ...

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
        ...

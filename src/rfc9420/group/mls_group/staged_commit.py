"""StagedCommit: verified commit waiting to be merged to storage (immutable, merge-on-write)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ...providers.storage import StorageProviderProtocol


@dataclass
class StagedCommit:
    """Represents a verified commit (own or received) not yet persisted.

    Holds the commit message, optional Welcome messages, and the new epoch state.
    Only .merge(storage) commits state to the StorageProvider; the group object
    is not mutated until the caller applies the commit (e.g. after merge).
    """

    commit_message: Any  # MLSPlaintext
    welcomes: list[Any]  # list[Welcome]
    new_epoch_state: dict[str, Any]
    prior_epoch: int
    group_id: bytes
    own_leaf_index: int
    tree_backend_id: str

    async def merge(self, storage: "StorageProviderProtocol") -> None:
        """Atomically persist this commit's state to the storage provider.

        Builds GroupEpochState from new_epoch_state and calls
        storage.merge_group_state(group_id, state). Must be atomic.
        """
        from .processing import build_group_epoch_state_for_storage

        state = build_group_epoch_state_for_storage(
            self.new_epoch_state,
            self.own_leaf_index,
            self.tree_backend_id,
        )
        await storage.merge_group_state(self.group_id, state)

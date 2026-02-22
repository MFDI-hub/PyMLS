"""Backend contract and factory for ratchet tree representations."""
from __future__ import annotations

from typing import Any, Callable, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from ..crypto.crypto_provider import CryptoProvider
    from .data_structures import UpdatePath
    from .key_packages import KeyPackage, LeafNode


BACKEND_ARRAY = "array"
BACKEND_PERFECT = "perfect"
BACKEND_LINKED = "linked"
DEFAULT_TREE_BACKEND = BACKEND_ARRAY


class RatchetTreeBackend(Protocol):
    """Protocol implemented by ratchet tree backend implementations."""

    backend_id: str

    @property
    def n_leaves(self) -> int: ...

    def get_node(self, index: int) -> Any: ...
    def add_leaf(self, key_package: "KeyPackage") -> int: ...
    def remove_leaf(self, index: int) -> None: ...
    def update_leaf(self, index: int, leaf_node: "LeafNode") -> None: ...
    def calculate_tree_hash(self) -> bytes: ...
    def resolve(self, node_index: int) -> list[Any]: ...
    def filtered_direct_path(self, node_index: int) -> list[int]: ...
    def create_update_path(
        self,
        committer_index: int,
        new_leaf_node: "LeafNode",
        group_context_bytes: bytes,
        excluded_leaf_pubkeys: "set[bytes] | None" = None,
    ) -> tuple["UpdatePath", bytes]: ...
    def merge_update_path(
        self, update_path: "UpdatePath", committer_index: int, group_context_bytes: bytes
    ) -> bytes: ...
    def _compute_parent_hash_for_leaf(self, leaf_index: int) -> bytes: ...
    def serialize_full_tree_for_welcome(self) -> bytes: ...
    def load_full_tree_from_welcome_bytes(self, data: bytes) -> None: ...
    def load_tree_from_welcome_bytes(self, data: bytes) -> None: ...
    def serialize_full_state(self) -> bytes: ...
    def load_full_state(self, data: bytes) -> None: ...


_BACKEND_FACTORIES: dict[str, Callable[["CryptoProvider"], RatchetTreeBackend]] = {}


def register_tree_backend(
    backend_id: str, factory: Callable[["CryptoProvider"], RatchetTreeBackend]
) -> None:
    """Register a backend factory by its stable backend ID."""
    _BACKEND_FACTORIES[backend_id] = factory


def _ensure_builtin_backends() -> None:
    if _BACKEND_FACTORIES:
        return
    # Lazy imports avoid module cycles at import time.
    from .ratchet_tree import RatchetTree
    from .ratchet_tree_linked import LinkedRatchetTree
    from .ratchet_tree_perfect import PerfectRatchetTree

    register_tree_backend(BACKEND_ARRAY, lambda crypto: RatchetTree(crypto))
    register_tree_backend(BACKEND_PERFECT, lambda crypto: PerfectRatchetTree(crypto))
    register_tree_backend(BACKEND_LINKED, lambda crypto: LinkedRatchetTree(crypto))


def create_tree_backend(
    crypto_provider: "CryptoProvider",
    backend_id: str = DEFAULT_TREE_BACKEND,
) -> RatchetTreeBackend:
    """Instantiate a backend by ID. Unknown values fall back to default."""
    _ensure_builtin_backends()
    factory = _BACKEND_FACTORIES.get(backend_id) or _BACKEND_FACTORIES[DEFAULT_TREE_BACKEND]
    return factory(crypto_provider)

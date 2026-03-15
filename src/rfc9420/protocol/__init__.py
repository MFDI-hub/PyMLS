"""Protocol-layer primitives and state machines for RFC9420 (RFC 9420)."""

from .tree.ratchet_tree_backend import (
    BACKEND_ARRAY,
    BACKEND_LINKED,
    BACKEND_PERFECT,
    DEFAULT_TREE_BACKEND,
    create_tree_backend,
)

# Compatibility: old import paths still resolve
import sys
from . import tree
sys.modules[__name__ + ".ratchet_tree_backend"] = tree.ratchet_tree_backend
sys.modules[__name__ + ".ratchet_tree"] = tree.ratchet_tree
sys.modules[__name__ + ".ratchet_tree_linked"] = tree.ratchet_tree_linked
sys.modules[__name__ + ".ratchet_tree_perfect"] = tree.ratchet_tree_perfect
sys.modules[__name__ + ".tree_math"] = tree.tree_math
sys.modules[__name__ + ".secret_tree"] = tree.secret_tree

__all__ = [
    "BACKEND_ARRAY",
    "BACKEND_LINKED",
    "BACKEND_PERFECT",
    "DEFAULT_TREE_BACKEND",
    "create_tree_backend",
]


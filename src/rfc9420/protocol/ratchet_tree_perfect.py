"""Perfect-tree backend facade.

This backend keeps protocol behavior identical to the default array backend while
exposing a distinct backend ID for applications that want to select a strict
tree mode. The current implementation reuses the proven RFC-compatible logic.
"""
from __future__ import annotations

from .ratchet_tree import RatchetTree


class PerfectRatchetTree(RatchetTree):
    """Ratchet tree backend identifier for perfect-tree mode."""

    backend_id = "perfect"

"""Link-based backend facade.

This backend provides a selectable backend ID for link-based deployments while
preserving wire/protocol behavior through the shared RFC-compatible core logic.
"""
from __future__ import annotations

from .ratchet_tree import RatchetTree


class LinkedRatchetTree(RatchetTree):
    """Ratchet tree backend identifier for link-based mode."""

    backend_id = "linked"

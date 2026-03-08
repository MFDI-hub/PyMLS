"""Link-based tree backend (RFC 9420 Appendix D).

Appendix D describes an alternative, link-based representation of the ratchet
tree. This backend intentionally delegates all behavior to the array-based
implementation (Appendix C) in RatchetTree. Wire format and protocol semantics
are identical; the "linked" backend ID allows deployments to select this
representation for future use (e.g., if a link-based storage implementation
is added) while guaranteeing RFC-compliant behavior today.
"""
from __future__ import annotations

from .ratchet_tree import RatchetTree


class LinkedRatchetTree(RatchetTree):
    """Ratchet tree backend for link-based mode (RFC 9420 Appendix D).

    Delegates to the array-based RatchetTree implementation. Protocol and
    wire behavior are unchanged; this is a selectable backend ID for
    deployments that prefer the link-based designation.
    """

    backend_id = "linked"

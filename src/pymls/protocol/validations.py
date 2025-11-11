from __future__ import annotations

from typing import Iterable, Set

from .data_structures import Proposal, AddProposal
from .key_packages import KeyPackage


class CommitValidationError(Exception):
    pass


def _extract_user_id_from_key_package_bytes(kp_bytes: bytes) -> str:
    kp = KeyPackage.deserialize(kp_bytes)
    identity = kp.leaf_node.credential.identity
    try:
        return identity.decode("utf-8")
    except Exception:
        # Fallback to hex if identity is not valid UTF-8
        return identity.hex()


def validate_unique_adds_by_user_id(proposals: Iterable[Proposal]) -> None:
    seen: Set[str] = set()
    for p in proposals:
        if isinstance(p, AddProposal):
            user_id = _extract_user_id_from_key_package_bytes(p.key_package)
            if user_id in seen:
                raise CommitValidationError(f"duplicate Add for user_id={user_id}")
            seen.add(user_id)


def validate_proposals_client_rules(proposals: Iterable[Proposal]) -> None:
    # DAVE 1.1.0+: All included proposals must be proposal references.
    # Our current model carries full proposals, so we only enforce uniqueness of Add by user ID.
    validate_unique_adds_by_user_id(proposals)
from __future__ import annotations

from typing import Iterable, Set

from .data_structures import Proposal, AddProposal, Commit, RemoveProposal, UpdateProposal
from .key_packages import KeyPackage
from ..extensions.extensions import parse_capabilities_data
from ..crypto.crypto_provider import CryptoProvider


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


def validate_proposals_client_rules(proposals: Iterable[Proposal], n_leaves: int) -> None:
    """
    Baseline client-side proposal checks:
    - Enforce uniqueness of Add by user ID.
    - Ensure Remove indices are within current tree size.
    """
    validate_unique_adds_by_user_id(proposals)
    for p in proposals:
        if isinstance(p, RemoveProposal):
            if p.removed < 0 or p.removed >= n_leaves:
                raise CommitValidationError(f"remove index out of range: {p.removed} not in [0, {n_leaves})")
        if isinstance(p, AddProposal):
            # Validate that capabilities payload (if present in LeafNode) parses
            try:
                kp = KeyPackage.deserialize(p.key_package)
                if kp.leaf_node.capabilities:
                    parse_capabilities_data(kp.leaf_node.capabilities)
            except Exception as e:
                raise CommitValidationError("invalid capabilities in key package") from e


def validate_commit_basic(commit: Commit) -> None:
    # Basic structural checks
    if commit.path is None and (len(commit.adds) > 0 or len(commit.removes) > 0):
        # In RFC, non-path commits are allowed in certain cases, but we don't support them.
        raise CommitValidationError("commit without path not supported in this implementation")
    # If proposal_refs are present, they must be non-empty opaque values
    for pref in getattr(commit, "proposal_refs", []):
        if not isinstance(pref, (bytes, bytearray)) or len(pref) == 0:
            raise CommitValidationError("invalid proposal reference encoding")


def validate_confirmation_tag(crypto: CryptoProvider, confirmation_key: bytes, commit_bytes: bytes, tag: bytes) -> None:
    expected = crypto.hmac_sign(confirmation_key, commit_bytes)[: len(tag)]
    if expected != tag:
        raise CommitValidationError("invalid confirmation tag")


def derive_ops_from_proposals(proposals: Iterable[Proposal]) -> tuple[list[int], list[bytes]]:
    removes: list[int] = []
    adds: list[bytes] = []
    for p in proposals:
        if isinstance(p, RemoveProposal):
            removes.append(p.removed)
        elif isinstance(p, AddProposal):
            adds.append(p.key_package)
        elif isinstance(p, UpdateProposal):
            # Updates affect committer path; no remove/add lists
            continue
    return removes, adds


def validate_commit_matches_referenced_proposals(commit: Commit, referenced: Iterable[Proposal]) -> None:
    """
    If a commit carries proposal references, ensure its removes/adds match
    the referenced proposals (MVP rule).
    """
    ref_removes, ref_adds = derive_ops_from_proposals(referenced)
    if commit.removes != ref_removes:
        raise CommitValidationError("commit removes do not match referenced proposals")
    if commit.adds != ref_adds:
        raise CommitValidationError("commit adds do not match referenced proposals")
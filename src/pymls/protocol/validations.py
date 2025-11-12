"""Client-side and commit validations for MLS proposals and commits (MVP)."""
from __future__ import annotations

from typing import Iterable, Set

from .data_structures import Proposal, AddProposal, Commit, RemoveProposal, UpdateProposal
from .key_packages import KeyPackage
from ..extensions.extensions import parse_capabilities_data
from ..crypto.crypto_provider import CryptoProvider


class CommitValidationError(Exception):
    """Raised when a commit or its related data fails validation checks."""
    pass


def _extract_user_id_from_key_package_bytes(kp_bytes: bytes) -> str:
    """Get a stable user ID string from a serialized KeyPackage's credential identity.

    Be lenient: if bytes are not a full KeyPackage, fall back to treating the
    input as the identity blob directly.
    """
    try:
        kp = KeyPackage.deserialize(kp_bytes)
        cred = kp.leaf_node.credential
        if cred is not None:
            identity = cred.identity
            try:
                return identity.decode("utf-8")
            except Exception:
                return identity.hex()
    except Exception:
        # Not a full KeyPackage; treat kp_bytes as identity
        try:
            return kp_bytes.decode("utf-8")
        except Exception:
            return kp_bytes.hex()
    # Fallback if credential was absent in a parsed KeyPackage
    return kp_bytes.hex()


def validate_unique_adds_by_user_id(proposals: Iterable[Proposal]) -> None:
    """Ensure there is at most one Add proposal per user identity in a commit batch."""
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
    """Basic structural checks for a Commit object."""
    # Basic structural checks
    # Path-less commits are allowed by RFC 9420 in several cases (e.g., external commits,
    # proposal-only commits, and re-initialization). Do not reject solely due to missing path.
    # If proposal_refs are present, they must be non-empty opaque values
    for pref in getattr(commit, "proposal_refs", []):
        if not isinstance(pref, (bytes, bytearray)) or len(pref) == 0:
            raise CommitValidationError("invalid proposal reference encoding")


def validate_confirmation_tag(crypto: CryptoProvider, confirmation_key: bytes, commit_bytes: bytes, tag: bytes) -> None:
    """Verify confirmation tag as HMAC(confirm_key, commit_bytes) truncated to tag length."""
    expected = crypto.hmac_sign(confirmation_key, commit_bytes)[: len(tag)]
    if expected != tag:
        raise CommitValidationError("invalid confirmation tag")


def derive_ops_from_proposals(proposals: Iterable[Proposal]) -> tuple[list[int], list[bytes]]:
    """Derive removes list and adds KeyPackage bytes from an iterable of proposals."""
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
"""Client-side and commit validations for MLS proposals and commits (MVP)."""
from __future__ import annotations

from typing import Iterable, Set

from .data_structures import Proposal, AddProposal, Commit, RemoveProposal, UpdateProposal, ProposalOrRef, ProposalOrRefType, GroupContextExtensionsProposal, ExternalInitProposal, ReInitProposal
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
        ln = kp.leaf_node
        if ln is not None:
            cred = ln.credential
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
                if kp.leaf_node and kp.leaf_node.capabilities:
                    parse_capabilities_data(kp.leaf_node.capabilities)
            except Exception as e:
                raise CommitValidationError("invalid capabilities in key package") from e


def validate_proposals_server_rules(proposals: Iterable[Proposal], committer_index: int, n_leaves: int) -> None:
    """
    Server-side proposal checks per RFC §12.2 (subset):
    - Enforce client-side rules.
    - No Remove of committer.
    - ReInit cannot be combined with any other proposal.
    """
    plist = list(proposals)
    validate_proposals_client_rules(plist, n_leaves)
    # No Remove of committer
    for p in plist:
        if isinstance(p, RemoveProposal) and p.removed == committer_index:
            raise CommitValidationError("commit cannot remove the committer")
    # ReInit cannot be combined with others
    has_reinit = any(isinstance(p, ReInitProposal) for p in plist)
    if has_reinit and len(plist) > 1:
        raise CommitValidationError("ReInit cannot be combined with other proposals")
    # No duplicate removes for the same leaf
    seen_removed: Set[int] = set()
    for p in plist:
        if isinstance(p, RemoveProposal):
            if p.removed in seen_removed:
                raise CommitValidationError(f"duplicate Remove for leaf index {p.removed}")
            seen_removed.add(p.removed)


def validate_commit_basic(commit: Commit) -> None:
    """Basic structural checks for a Commit object with union proposals list."""
    # Path-less commits are allowed by RFC 9420 in several cases.
    # Ensure proposals vector is well-formed.
    if not isinstance(commit.proposals, list):
        raise CommitValidationError("commit proposals must be a list")
    for por in commit.proposals:
        if not isinstance(por, ProposalOrRef):
            raise CommitValidationError("invalid proposal entry type")
        if por.typ == ProposalOrRefType.REFERENCE:
            if por.reference is None or not isinstance(por.reference, (bytes, bytearray)) or len(por.reference) == 0:
                raise CommitValidationError("invalid proposal reference encoding")


def commit_path_required(proposals: Iterable[Proposal]) -> bool:
    """
    Determine if a Commit MUST carry a non-empty path (RFC §12.4).
    Path required if proposals vector is empty or contains any of:
      - Update, Remove, ExternalInit, GroupContextExtensions.
    """
    plist = list(proposals)
    if len(plist) == 0:
        return True
    for p in plist:
        if isinstance(p, (UpdateProposal, RemoveProposal, ExternalInitProposal, GroupContextExtensionsProposal)):
            return True
    return False


def validate_confirmation_tag(crypto: CryptoProvider, confirmation_key: bytes, confirmed_transcript_hash: bytes, tag: bytes) -> None:
    """Verify confirmation_tag == MAC(confirmation_key, confirmed_transcript_hash) per RFC 9420 §8.1."""
    expected = crypto.hmac_sign(confirmation_key, confirmed_transcript_hash)
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
    If a commit carries proposal references, ensure such references exist and are non-empty.
    Detailed matching of effects is enforced by higher-level processing.
    """
    has_refs = any(por.typ == ProposalOrRefType.REFERENCE for por in commit.proposals)
    if has_refs and (referenced is None or len(list(referenced)) == 0):
        raise CommitValidationError("commit references proposals but none were resolved")
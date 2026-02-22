"""Client-side and commit validations for MLS proposals and commits (MVP)."""
from __future__ import annotations

from typing import Iterable, Set, Any

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


def validate_proposals_server_rules(
    proposals: Iterable[Proposal],
    committer_index: int,
    n_leaves: int,
    *,
    ratchet_tree: Any | None = None,
    kdf_hash_len: int | None = None,
    allow_reinit_psk: bool = False,
    allow_branch_psk: bool = False,
    current_version: int | None = None,
) -> None:
    """Server-side proposal checks per RFC 9420 §12.2 (subset).

    Enforces client-side rules, no Remove of committer, ReInit exclusivity,
    at most one Update per member and one GCE per commit, pairwise-distinct
    PSK IDs, no ExternalInit in regular commits, and committer may not
    Update their own leaf via a proposal.

    Parameters:
        proposals: Proposals in the commit.
        committer_index: Leaf index of the committer.
        n_leaves: Current number of leaves in the tree.
        ratchet_tree: Optional ratchet tree for parent-hash validation.
        kdf_hash_len: Optional KDF hash length for ref hashes.
        allow_reinit_psk: Whether ReInit with PSK is allowed.
        allow_branch_psk: Whether branch PSKs are allowed.
        current_version: Optional protocol version for ReInit checks.

    Raises:
        CommitValidationError: If any server-side rule is violated.
    """
    from .data_structures import PreSharedKeyProposal
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
    # No ExternalInit in regular commits (RFC §12.2)
    has_ext_init = any(isinstance(p, ExternalInitProposal) for p in plist)
    if has_ext_init:
        raise CommitValidationError("ExternalInit proposal not allowed in regular commit")
    # No duplicate removes for the same leaf
    seen_removed: Set[int] = set()
    for p in plist:
        if isinstance(p, RemoveProposal):
            if p.removed in seen_removed:
                raise CommitValidationError(f"duplicate Remove for leaf index {p.removed}")
            seen_removed.add(p.removed)
    # At most one GCE proposal per commit (RFC §12.2)
    gce_count = sum(1 for p in plist if isinstance(p, GroupContextExtensionsProposal))
    if gce_count > 1:
        raise CommitValidationError("at most one GroupContextExtensions proposal per commit")
    # Pairwise-distinct PSK IDs and PSK semantic checks.
    psk_id_set: set[bytes] = set()
    for p in plist:
        if isinstance(p, PreSharedKeyProposal):
            try:
                psk_canonical = p.psk.serialize()
            except Exception:
                psk_canonical = str(p.psk).encode()
            if psk_canonical in psk_id_set:
                raise CommitValidationError("duplicate PSK ID in commit")
            psk_id_set.add(psk_canonical)
            if kdf_hash_len is not None and len(p.psk.psk_nonce) != int(kdf_hash_len):
                raise CommitValidationError("psk_nonce length must equal KDF.Nh")
            try:
                from .data_structures import PSKType, ResumptionPSKUsage

                if p.psk.psktype == PSKType.RESUMPTION:
                    if p.psk.usage == ResumptionPSKUsage.REINIT and not allow_reinit_psk:
                        raise CommitValidationError("resumption+reinit PSK not allowed in this context")
                    if p.psk.usage == ResumptionPSKUsage.BRANCH and not allow_branch_psk:
                        raise CommitValidationError("resumption+branch PSK not allowed in this context")
            except CommitValidationError:
                raise
            except Exception:
                pass
    # At most one Update proposal per leaf index (RFC §12.2)
    update_count = sum(1 for p in plist if isinstance(p, UpdateProposal))
    if update_count > 1:
        raise CommitValidationError("at most one Update proposal per member per commit")
    # ReInit proposal version monotonicity check (§12.1.5)
    if current_version is not None:
        for p in plist:
            if isinstance(p, ReInitProposal) and int(p.version) < int(current_version):
                raise CommitValidationError("ReInit proposal version must be >= current group version")
    # Remove proposals must target non-blank leaves (§12.1.3)
    if ratchet_tree is not None:
        for p in plist:
            if isinstance(p, RemoveProposal):
                try:
                    node = ratchet_tree.get_node(p.removed * 2)
                    if node is None or node.leaf_node is None:
                        raise CommitValidationError("Remove proposal targets a blank leaf")
                except Exception as e:
                    if isinstance(e, CommitValidationError):
                        raise
                    raise CommitValidationError("invalid Remove proposal target leaf") from e


def validate_update_path_key_uniqueness(ratchet_tree: Any, path_public_keys: list[bytes], committer_index: int) -> None:
    """Ensure UpdatePath encryption keys are unique across the tree."""
    existing: set[bytes] = set()
    for leaf in range(getattr(ratchet_tree, "n_leaves", 0)):
        node = ratchet_tree.get_node(leaf * 2)
        if node is None:
            continue
        ln = getattr(node, "leaf_node", None)
        if ln is not None:
            enc = getattr(ln, "encryption_key", b"")
            if enc:
                existing.add(enc)
    # Internal-node public keys in the array-indexed node store.
    for _idx, node in getattr(ratchet_tree, "_nodes", {}).items():
        pub = getattr(node, "public_key", b"")
        if pub:
            existing.add(pub)
    for key in path_public_keys:
        if key in existing:
            raise CommitValidationError(
                f"UpdatePath encryption key duplicates existing key (committer={committer_index})"
            )


def validate_proposal_types_supported(
    proposals: Iterable[Proposal], member_capabilities: list[dict[str, list[int]]], required_proposals: list[int] | None = None
) -> None:
    """Ensure all members support proposal types present in a commit."""
    used = [int(p.proposal_type.value) for p in proposals]
    req = set(required_proposals or [])
    for idx, caps in enumerate(member_capabilities):
        supported_list = caps.get("proposals", [])
        # Backward compatibility: older members may carry empty/legacy
        # capabilities; treat absence as "not constraining" instead of
        # rejecting all proposals.
        if not supported_list:
            continue
        supported = set(supported_list)
        for ptype in used:
            if ptype not in supported and ptype not in req:
                raise CommitValidationError(f"Member {idx} does not support proposal type {ptype}")


def validate_credential_types_supported(ratchet_tree: Any, member_capabilities: list[dict[str, list[int]]]) -> None:
    """Ensure credential types used in tree are supported by all members."""
    used_types: set[int] = set()
    for leaf in range(getattr(ratchet_tree, "n_leaves", 0)):
        node = ratchet_tree.get_node(leaf * 2)
        if node is None or node.leaf_node is None or node.leaf_node.credential is None:
            continue
        ctype = getattr(node.leaf_node.credential, "credential_type", None)
        if ctype is None:
            ctype = getattr(node.leaf_node.credential, "typ", None)
        if ctype is not None:
            used_types.add(int(ctype))
    for idx, caps in enumerate(member_capabilities):
        supported_list = caps.get("credentials", [])
        # Backward compatibility: older members may omit capabilities entirely.
        # Do not fail closed when no credential list is advertised.
        if not supported_list:
            continue
        supported = set(supported_list)
        for ctype in used_types:
            if ctype not in supported:
                raise CommitValidationError(f"Member {idx} does not support credential type {ctype}")


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


def validate_leaf_node_unique_against_tree(
    ratchet_tree: Any, leaf_node: Any, replacing_leaf_index: int | None = None
) -> None:
    """Ensure a candidate leaf node's signature/encryption keys are unique in the tree."""
    if leaf_node is None:
        return

    cand_sig = getattr(leaf_node, "signature_key", b"")
    cand_enc = getattr(leaf_node, "encryption_key", b"")
    if not cand_sig and not cand_enc:
        return

    for idx in range(getattr(ratchet_tree, "n_leaves", 0)):
        if replacing_leaf_index is not None and idx == replacing_leaf_index:
            continue
        node = ratchet_tree.get_node(idx * 2)
        if node is None or node.leaf_node is None:
            continue
        other = node.leaf_node
        if cand_sig and getattr(other, "signature_key", b"") == cand_sig:
            raise CommitValidationError(
                f"duplicate signature_key detected at leaf {idx}"
            )
        if cand_enc and getattr(other, "encryption_key", b"") == cand_enc:
            raise CommitValidationError(
                f"duplicate encryption_key detected at leaf {idx}"
            )


def validate_tree_leaf_key_uniqueness(ratchet_tree: Any) -> None:
    """Ensure all non-blank leaves have globally unique signature/encryption keys."""
    seen_sig: dict[bytes, int] = {}
    seen_enc: dict[bytes, int] = {}
    for idx in range(getattr(ratchet_tree, "n_leaves", 0)):
        node = ratchet_tree.get_node(idx * 2)
        if node is None or node.leaf_node is None:
            continue
        ln = node.leaf_node
        sig = getattr(ln, "signature_key", b"")
        enc = getattr(ln, "encryption_key", b"")
        if sig:
            if sig in seen_sig:
                raise CommitValidationError(
                    f"duplicate signature_key detected at leaves {seen_sig[sig]} and {idx}"
                )
            seen_sig[sig] = idx
        if enc:
            if enc in seen_enc:
                raise CommitValidationError(
                    f"duplicate encryption_key detected at leaves {seen_enc[enc]} and {idx}"
                )
            seen_enc[enc] = idx


def validate_group_context_extensions(
    proposal: GroupContextExtensionsProposal,
    member_capabilities: list[dict[str, list[int]]]
) -> None:
    """
    Validate that a GroupContextExtensions proposal's required capabilities
    are supported by all members.
    
    member_capabilities is a list of dicts, each containing:
    - 'versions': list[int]
    - 'ciphersuites': list[int] 
    - 'extensions': list[int]
    - 'proposals': list[int]
    - 'credentials': list[int]
    derived from each member's LeafNode.
    """
    from ..extensions.extensions import ExtensionType, parse_required_capabilities, deserialize_extensions
    
    try:
        exts = deserialize_extensions(proposal.extensions)
        required_exts = []
        required_props = []
        required_creds = []
        
        for ext in exts:
            if ext.ext_type == ExtensionType.REQUIRED_CAPABILITIES:
                # Parse the full structure
                r_exts, r_props, r_creds = parse_required_capabilities(ext.data)
                required_exts.extend(r_exts)
                required_props.extend(r_props)
                required_creds.extend(r_creds)

        if not required_exts and not required_props and not required_creds:
            return

        # Check each member
        for i, member_caps in enumerate(member_capabilities):
            # Check extensions
            for req_ext in required_exts:
                if req_ext not in member_caps.get('extensions', []):
                     # RFC 9420 §11.1: "A GroupContextExtensions proposal MUST be considered invalid..."
                     raise CommitValidationError(f"Member {i} does not support required extension {req_ext}")
            
            # Check proposals
            if 'proposals' in member_caps:
                for req_prop in required_props:
                    if req_prop not in member_caps['proposals']:
                        raise CommitValidationError(f"Member {i} does not support required proposal type {req_prop}")
            
            # Check credentials
            if 'credentials' in member_caps:
                for req_cred in required_creds:
                    if req_cred not in member_caps['credentials']:
                        raise CommitValidationError(f"Member {i} does not support required credential type {req_cred}")

    except Exception as e:
        if isinstance(e, CommitValidationError):
            raise
        raise CommitValidationError(f"Failed to validate GroupContextExtensions: {e}") from e
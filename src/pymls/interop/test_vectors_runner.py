from __future__ import annotations

import json
import os
from typing import Dict, Any

from ..protocol.key_schedule import KeySchedule
from ..protocol.data_structures import GroupContext
from ..crypto.crypto_provider import CryptoProvider
from ..protocol import tree_math
from ..protocol.secret_tree import SecretTree
from ..protocol.messages import ContentType, FramedContent, AuthenticatedContentTBS
from ..protocol.data_structures import GroupInfo as GroupInfoStruct, Signature


def _run_key_schedule_vector(vec: Dict[str, Any], crypto: CryptoProvider) -> None:
    """
    Minimal execution of a key schedule test vector:
    expects fields: init_secret, commit_secret, group_context, psk_secret (optional)
    All byte fields are hex strings.
    """
    def h(b: str) -> bytes:
        return bytes.fromhex(b)

    gc = GroupContext(
        group_id=h(vec["group_context"]["group_id"]),
        epoch=int(vec["group_context"]["epoch"]),
        tree_hash=h(vec["group_context"]["tree_hash"]),
        confirmed_transcript_hash=h(vec["group_context"]["confirmed_transcript_hash"]),
    )
    ks = KeySchedule(
        init_secret=h(vec["init_secret"]),
        commit_secret=h(vec["commit_secret"]),
        group_context=gc,
        psk_secret=h(vec["psk_secret"]) if "psk_secret" in vec and vec["psk_secret"] else None,
        crypto_provider=crypto,
    )
    # Optional assertions if expected secrets are provided
    for field in ["epoch_secret", "handshake_secret", "application_secret", "exporter_secret", "external_secret"]:
        if field in vec.get("expected", {}):
            exp = h(vec["expected"][field])
            got = getattr(ks, field)
            if callable(got):
                got = got()
            assert getattr(ks, field) == exp, f"{field} mismatch"


def _run_tree_math_vector(vec: Dict[str, Any], _crypto: CryptoProvider) -> None:
    """
    Execute basic checks for tree math vectors.
    Accepts keys like: n_leaves, root, cases [{x, left, right, parent}].
    """
    n = int(vec.get("n_leaves", 0))
    if "root" in vec:
        exp_root = int(vec["root"])
        got_root = tree_math.root(n)
        assert got_root == exp_root, "root mismatch"
    for case in vec.get("cases", []):
        x = int(case["x"])
        if "left" in case:
            try:
                assert tree_math.left(x) == int(case["left"]), "left mismatch"
            except ValueError:
                # leaves have no children; allow vectors to mark accordingly
                if case["left"] != "error":
                    raise
        if "right" in case:
            try:
                assert tree_math.right(x, n) == int(case["right"]), "right mismatch"
            except ValueError:
                if case["right"] != "error":
                    raise
        if "parent" in case:
            try:
                assert tree_math.parent(x, n) == int(case["parent"]), "parent mismatch"
            except ValueError:
                if case["parent"] != "error":
                    raise


def _run_secret_tree_vector(vec: Dict[str, Any], crypto: CryptoProvider) -> None:
    """
    Check derivations in the SecretTree (RFC 9420 §9.2).
    Expected keys:
      - application_secret, handshake_secret (hex)
      - leaf (int), generation (int), n_leaves (int, optional)
      - expected: { app_key, app_nonce, hs_key, hs_nonce } (hex)
    """
    h = lambda b: bytes.fromhex(b) if isinstance(b, str) else b
    leaf = int(vec.get("leaf", 0))
    n_leaves = int(vec.get("n_leaves", max(leaf + 1, 1)))
    st = SecretTree(h(vec["application_secret"]), h(vec["handshake_secret"]), crypto, n_leaves=n_leaves)
    gen = int(vec.get("generation", 0))
    app_key, app_nonce, _ = st.application_for(leaf, gen)
    hs_key, hs_nonce, _ = st.handshake_for(leaf, gen)
    exp = vec.get("expected", {})
    if "app_key" in exp:
        assert app_key == h(exp["app_key"]), "app_key mismatch"
    if "app_nonce" in exp:
        assert app_nonce == h(exp["app_nonce"]), "app_nonce mismatch"
    if "hs_key" in exp:
        assert hs_key == h(exp["hs_key"]), "hs_key mismatch"
    if "hs_nonce" in exp:
        assert hs_nonce == h(exp["hs_nonce"]), "hs_nonce mismatch"


def _run_message_protection_vector(vec: Dict[str, Any], crypto: CryptoProvider) -> None:
    """
    Very light-weight check of MLSPlaintext TBS formatting for handshake messages.
    Expected keys:
      - group_id (hex), epoch (int), sender (int), authenticated_data (hex)
      - content (hex), content_type ("PROPOSAL"|"COMMIT")
      - expected: { tbs (hex) }
    """
    h = lambda b: bytes.fromhex(b) if isinstance(b, str) else b
    ct_map = {"PROPOSAL": ContentType.PROPOSAL, "COMMIT": ContentType.COMMIT, "APPLICATION": ContentType.APPLICATION}
    fc = FramedContent(content_type=ct_map[vec.get("content_type", "PROPOSAL")], content=h(vec.get("content", "")))
    tbs = AuthenticatedContentTBS(
        group_id=h(vec.get("group_id", "")),
        epoch=int(vec.get("epoch", 0)),
        sender_leaf_index=int(vec.get("sender", 0)),
        authenticated_data=h(vec.get("authenticated_data", "")),
        framed_content=fc,
    )
    if "expected" in vec and "tbs" in vec["expected"]:
        assert tbs.serialize() == h(vec["expected"]["tbs"]), "tbs mismatch"


def _run_welcome_groupinfo_vector(vec: Dict[str, Any], crypto: CryptoProvider) -> None:
    """
    Validate GroupInfo tbs and signature if inputs provided.
    Expected keys:
      - group_context: { group_id (hex), epoch, tree_hash (hex), confirmed_transcript_hash (hex) }
      - extensions (hex), signature (hex), signer_key (hex, optional)
      - expected: { tbs (hex) }
    """
    h = lambda b: bytes.fromhex(b) if isinstance(b, str) else b
    gc = GroupContext(
        group_id=h(vec["group_context"]["group_id"]),
        epoch=int(vec["group_context"]["epoch"]),
        tree_hash=h(vec["group_context"]["tree_hash"]),
        confirmed_transcript_hash=h(vec["group_context"]["confirmed_transcript_hash"]),
    )
    gi = GroupInfoStruct(gc, signature=Signature(h(vec.get("signature", ""))), extensions=h(vec.get("extensions", "")))
    if "expected" in vec and "tbs" in vec["expected"]:
        assert gi.tbs_serialize() == h(vec["expected"]["tbs"]), "groupinfo tbs mismatch"
    if "signer_key" in vec and vec["signer_key"]:
        crypto.verify(h(vec["signer_key"]), gi.tbs_serialize(), gi.signature.value)


def ingest_and_run_vectors(directory: str, crypto: CryptoProvider) -> Dict[str, int]:
    """
    Load JSON test vectors from a directory and run known types.
    Returns summary counts.
    """
    summary = {"total": 0, "passed": 0, "failed": 0, "skipped": 0}
    for fname in os.listdir(directory):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(directory, fname)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            summary["skipped"] += 1
            continue
        summary["total"] += 1
        try:
            vtype = data.get("type", "")
            if vtype == "key_schedule":
                _run_key_schedule_vector(data, crypto)
            elif vtype == "tree_math":
                _run_tree_math_vector(data, crypto)
            elif vtype == "secret_tree":
                _run_secret_tree_vector(data, crypto)
            elif vtype == "message_protection":
                _run_message_protection_vector(data, crypto)
            elif vtype == "welcome_groupinfo":
                _run_welcome_groupinfo_vector(data, crypto)
            else:
                summary["skipped"] += 1
                continue
            summary["passed"] += 1
        except AssertionError:
            summary["failed"] += 1
        except Exception:
            summary["failed"] += 1
    return summary


if __name__ == "__main__":
    import argparse
    from ..crypto.default_crypto_provider import DefaultCryptoProvider

    parser = argparse.ArgumentParser(description="Run MLS RFC 9420 test vectors")
    parser.add_argument("dir", help="Directory with JSON test vectors")
    parser.add_argument("--suite", type=lambda x: int(x, 0), default=0x0001, help="MLS ciphersuite id (e.g., 0x0001)")
    args = parser.parse_args()

    crypto = DefaultCryptoProvider(args.suite)
    result = ingest_and_run_vectors(args.dir, crypto)
    print(json.dumps(result, indent=2))


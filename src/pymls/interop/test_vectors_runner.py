from __future__ import annotations

import json
import os
from typing import Dict, Any

from ..protocol.key_schedule import KeySchedule
from ..protocol.data_structures import GroupContext
from ..crypto.crypto_provider import CryptoProvider


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
            else:
                summary["skipped"] += 1
                continue
            summary["passed"] += 1
        except AssertionError:
            summary["failed"] += 1
        except Exception:
            summary["failed"] += 1
    return summary


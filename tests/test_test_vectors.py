"""
Pytest for MLS test vectors in mls-implementations/test-vectors/.

Runs spec-format verification for each JSON file (and each vector in array files).
Skips the entire module if the test-vectors directory is missing. Individual
vectors may still be skipped for unsupported ciphersuites or key formats, but
all vector types have runner functions implemented.
"""

from __future__ import annotations

import json
import os
import pytest

# Resolve path to test-vectors directory (relative to repo root).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VECTORS_DIR = os.path.join(ROOT, "mls-implementations", "test-vectors")


def _vectors_dir_exists():
    return os.path.isdir(VECTORS_DIR)


def _list_vector_files():
    if not _vectors_dir_exists():
        return []
    return [f for f in os.listdir(VECTORS_DIR) if f.endswith(".json")]


def _load_vectors_file(fname: str):
    path = os.path.join(VECTORS_DIR, fname)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _filename_to_runner():
    """Map test-vectors filename (e.g. tree-math.json) to (runner_name, need_crypto)."""
    from test_vectors_runner import (
        run_tree_math_vector_spec,
        run_deserialization_vector_spec,
        run_crypto_basics_vector_spec,
        run_secret_tree_vector_spec,
        run_key_schedule_vector_spec,
        run_messages_vector_spec,
        run_transcript_hashes_vector_spec,
        run_welcome_vector_spec,
        run_tree_operations_vector_spec,
        run_tree_validation_vector_spec,
        run_treekem_vector_spec,
        run_psk_secret_vector_spec,
        run_message_protection_vector_spec,
        run_passive_client_vector_spec,
    )

    return {
        "tree-math.json": (run_tree_math_vector_spec, False),
        "deserialization.json": (run_deserialization_vector_spec, False),
        "crypto-basics.json": (run_crypto_basics_vector_spec, True),
        "secret-tree.json": (run_secret_tree_vector_spec, True),
        "key-schedule.json": (run_key_schedule_vector_spec, True),
        "messages.json": (run_messages_vector_spec, True),
        "transcript-hashes.json": (run_transcript_hashes_vector_spec, True),
        "welcome.json": (run_welcome_vector_spec, True),
        "tree-operations.json": (run_tree_operations_vector_spec, True),
        "tree-validation.json": (run_tree_validation_vector_spec, True),
        "treekem.json": (run_treekem_vector_spec, True),
        "psk_secret.json": (run_psk_secret_vector_spec, True),
        "message-protection.json": (run_message_protection_vector_spec, True),
        "passive-client-random.json": (run_passive_client_vector_spec, True),
        "passive-client-welcome.json": (run_passive_client_vector_spec, True),
        "passive-client-handling-commit.json": (run_passive_client_vector_spec, True),
    }


def _collect_vector_ids():
    """Collect (fname, index) for every vector in every file."""
    if not _vectors_dir_exists():
        return []
    runner_map = _filename_to_runner()
    out = []
    for fname in sorted(_list_vector_files()):
        if fname not in runner_map:
            continue
        try:
            data = _load_vectors_file(fname)
        except Exception:
            continue
        if isinstance(data, list):
            for i in range(len(data)):
                out.append((fname, i))
        else:
            out.append((fname, 0))
    return out


@pytest.mark.skipif(not _vectors_dir_exists(), reason="mls-implementations/test-vectors not found")
@pytest.mark.parametrize(
    "fname,vec_index",
    _collect_vector_ids(),
    ids=lambda x: f"{x[0]}[{x[1]}]" if isinstance(x, tuple) else str(x),
)
def test_vector_spec(fname, vec_index):
    """Run spec-format verification for one test vector."""
    from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
    from rfc9420.crypto.ciphersuites import CipherSuiteId, get_ciphersuite_by_id

    runner_map = _filename_to_runner()
    if fname not in runner_map:
        pytest.skip(f"no runner for {fname}")
    runner_fn, need_crypto = runner_map[fname]
    data = _load_vectors_file(fname)
    vec = data[vec_index] if isinstance(data, list) else data

    if need_crypto:
        cipher_suite = vec.get("cipher_suite")
        if cipher_suite is not None:
            if get_ciphersuite_by_id(int(cipher_suite)) is None:
                pytest.skip(f"unsupported ciphersuite {cipher_suite}")
            crypto = DefaultCryptoProvider(int(cipher_suite))
        else:
            crypto = DefaultCryptoProvider(
                CipherSuiteId.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
            )
    else:
        crypto = None

    try:
        if need_crypto:
            runner_fn(vec, crypto)
        else:
            runner_fn(vec)
    except NotImplementedError as e:
        pytest.skip(str(e))

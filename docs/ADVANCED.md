# Advanced MLS Features (PyMLS)

Status: MVP implementations matured toward RFC 9420 compliance; key refinements implemented.

## Proposal-by-Reference
- Proposals are cached on receipt; commits include `proposal_refs`.
- Commit processing checks that `adds`/`removes` match referenced proposals.

## External Init / External Commit
- Group publishes EXTERNAL_PUB in `GroupInfo` and stores on join.
- `external_commit(kp, kem_pub)` creates a path-less Commit (ExternalInit + Add) signed with the group's external key.
- `process_external_commit(plaintext)` verifies using external pub key (no membership tag) and applies commit.

## Pre-Shared Keys (PSKs), Binders, and Resumption
- `create_psk_proposal(psk_id, signing_key)` queues PSK usage.
- Commits now carry a PSK binder in `authenticated_data`, computed over a PSK preimage and the commit.
- Binder is verified on receipt (configurable strictness). PSK is integrated into the key schedule.
- `get_resumption_psk()` exports current resumption PSK.

## Re-Initialization
- `reinit_group_to(new_group_id, signing_key)` queues ReInit and emits a path-less Commit.
- On receipt, the group migrates to the new `group_id` and resets epoch (context migration).

## Credentials
- KeyPackage verification checks that the credential public key matches the leaf signature key.
- X.509 credential container is supported via `X509Credential.verify_chain(trust_roots)`.
- `MLSGroup.set_trust_roots()` configures trust anchors for chain validation.

## Interop & Testing
- Interop helpers to export/import MLSPlaintext/MLSCiphertext hex.
- RFC 9420 test vector ingestion runner (`interop/test_vectors_runner.py`).
- Negative tests for signature and proposal-ref validation; PSK binder presence; padding invariants.

## Feature Flags & Policy
- `set_strict_psk_binders(True|False)` to enforce/relax binder verification (default: True).

## Roadmap
- Broaden vector coverage (tree math, transcript hashes).
- Full X.509 policy including EKU/keyUsage checks and revocation (OCSP/CRL).
- Interop CLI and extended negative/fuzz tests.



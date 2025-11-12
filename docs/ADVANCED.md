# Advanced MLS Features (PyMLS)

Status: MVP implementations for common advanced features, with RFC-compliant refinements planned.

## Proposal-by-Reference
- Proposals are cached on receipt; commits include `proposal_refs`.
- Commit processing checks that `adds`/`removes` match referenced proposals.

## External Init / External Public Key
- Group publishes EXTERNAL_PUB in `GroupInfo` and stores on join.
- Helper: `external_commit_add_member(kp, kem_pub, signing_key)` creates ExternalInit+Add and commits.
- `process_external_commit(plaintext)` verifies using external pub key and applies commit.

## Pre-Shared Keys (PSKs) and Resumption
- `create_psk_proposal(psk_id, signing_key)` queues PSK usage.
- Commit derives a PSK secret (MVP) and includes it in the key schedule.
- `get_resumption_psk()` exports current resumption PSK.

## Re-Initialization
- `reinit_group_to(new_group_id, signing_key)` queues ReInit and commits (MVP).

## Credentials
- KeyPackage verification checks that the credential public key matches the leaf signature key.
- X.509 credential container defined; full chain verification is future work.

## Interop & Testing
- Interop helpers to export/import MLSPlaintext/MLSCiphertext hex.
- Negative tests for signature and proposal-ref validation.
- Simple fuzz tests for plaintext/ciphertext decoding.

## Roadmap
- Full external commit/join, reinit flows (pathless cases), PSK binders.
- Robust credential validation (X.509) and policy.
- RFC vectors ingestion and interop CLI.
- Negative/fuzz test expansion.



# PyMLS

Pure Messaging Layer Security (MLS, RFC 9420) library in Python.

## Overview

PyMLS is a minimal, pragmatic implementation of the Messaging Layer Security protocol as specified in RFC 9420. The library provides a clean Python API for creating and managing MLS groups, handling cryptographic operations, and interoperating with other MLS implementations.

### Status

- ✅ Core wire types (`MLSPlaintext`, `MLSCiphertext`, `Welcome`, `GroupInfo`) implemented
- ✅ Group state machine for Add/Update/Remove, commit create/process (RFC-aligned ordering)
- ✅ Ratchet tree with RFC-style parent-hash validation
- ✅ Welcome processing with full ratchet_tree extension (internal nodes included)
- ✅ Ergonomic API: `pymls.Group`
- ✅ RFC 9420 test vector support
- ✅ External commit and PSK support
- ✅ X.509 credential verification and revocation helpers

## Quickstart

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.pymls import Group, DefaultCryptoProvider
from src.pymls.protocol.key_packages import KeyPackage, LeafNode
from src.pymls.protocol.data_structures import Credential, Signature

crypto = DefaultCryptoProvider()  # MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

def make_member(identity: bytes):
    kem_sk = X25519PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    sig_sk = Ed25519PrivateKey.generate()
    sig_pk = sig_sk.public_key()
    cred = Credential(identity=identity, public_key=sig_pk.public_bytes_raw())
    leaf = LeafNode(
        encryption_key=kem_pk.public_bytes_raw(),
        signature_key=sig_pk.public_bytes_raw(),
        credential=cred,
        capabilities=b"",
        parent_hash=b"",
    )
    sig = sig_sk.sign(leaf.serialize())
    kp = KeyPackage(leaf, Signature(sig))
    return kp, kem_sk.private_bytes_raw(), sig_sk.private_bytes_raw()

# Creator (A)
kp_a, kem_sk_a, sig_sk_a = make_member(b"userA")
group = Group.create(b"group1", kp_a, crypto)

# Joiner (B)
kp_b, kem_sk_b, sig_sk_b = make_member(b"userB")
prop = group.add(kp_b, sig_sk_a)
group.process_proposal(prop, 0)
commit_pt, welcomes = group.commit(sig_sk_a)

group_b = Group.join_from_welcome(welcomes[0], kem_sk_b, crypto)

ct = group.protect(b"hello")
sender, pt = group_b.unprotect(ct)
print(sender, pt)  # 0, b'hello'
```

## Installation

This project uses `pyproject.toml` (PEP 621). Prefer `uv` for dependency management:

```bash
pipx install uv  # once
uv sync --dev

# Lint, type-check, test
uv run ruff check .
uv run mypy src
uv run pytest -q
```

## Core Features

### Group Operations

The `Group` class provides a high-level API for MLS group management:

- **`Group.create(group_id, key_package, crypto)`**: Create a new group with an initial member
- **`Group.join_from_welcome(welcome, hpke_private_key, crypto)`**: Join an existing group via Welcome message
- **`group.add(key_package, signing_key)`**: Create an Add proposal
- **`group.update(leaf_node, signing_key)`**: Create an Update proposal
- **`group.remove(removed_index, signing_key)`**: Create a Remove proposal
- **`group.process_proposal(message, sender_leaf_index)`**: Process a received proposal
- **`group.commit(signing_key)`**: Create a commit with pending proposals
- **`group.apply_commit(message, sender_leaf_index)`**: Apply a received commit
- **`group.protect(application_data)`**: Encrypt application data
- **`group.unprotect(message)`**: Decrypt application ciphertext

### Ciphersuites

PyMLS supports all RFC 9420 §16.3 ciphersuites:

- `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001) - Default
- `MLS_128_DHKEMP256_AES128GCM_SHA256_P256` (0x0002)
- `MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519` (0x0003)
- `MLS_128_DHKEMP256_CHACHAPOLY_SHA256_P256` (0x0004)
- `MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448` (0x0005)
- `MLS_256_DHKEMP521_AES256GCM_SHA512_P521` (0x0006)
- `MLS_256_DHKEMX448_CHACHAPOLY_SHA512_Ed448` (0x0007)
- `MLS_256_DHKEMP521_CHACHAPOLY_SHA512_P521` (0x0008)

Select a ciphersuite when creating a `DefaultCryptoProvider`:

```python
crypto = DefaultCryptoProvider(suite_id=0x0001)  # Default
```

## Advanced Features

### Proposal-by-Reference

Proposals are cached on receipt using RFC 9420 §5.2 proposal references. Commits include `proposal_refs` that reference cached proposals. Commit processing validates that `adds`/`removes` match the referenced proposals.

### External Commit

Groups publish an `EXTERNAL_PUB` extension in `GroupInfo` for external parties to join without a Welcome. External commits are path-less commits signed with the group's external key (no membership tag required).

```python
# On the group side: external commit adds a member
commit, welcomes = group._inner.external_commit(key_package, kem_public_key)

# On the external party side: process external commit
group._inner.process_external_commit(commit_message)
```

### Pre-Shared Keys (PSKs)

PSK proposals bind PSKs to commits via a PSK binder in `authenticated_data`. The binder is computed over a PSK preimage and the commit content. PSKs are integrated into the epoch key schedule.

```python
# Create a PSK proposal
psk_proposal = group._inner.create_psk_proposal(psk_id, signing_key)
group.process_proposal(psk_proposal, sender_index)

# PSK binder is automatically computed and verified during commit processing
commit, welcomes = group.commit(signing_key)
```

PSK binder verification is strict by default. Configure via `MLSGroup.set_strict_psk_binders(False)` to relax verification.

### Resumption PSK

Export the current resumption PSK for future group resumption:

```python
resumption_psk = group._inner.get_resumption_psk()
```

### Re-Initialization

Re-init allows migrating a group to a new `group_id` and resetting the epoch:

```python
# Queue ReInit and create commit
commit, welcomes = group._inner.reinit_group_to(new_group_id, signing_key)

# On receipt, the group migrates to the new group_id and resets epoch
group.apply_commit(commit, sender_index)
```

### Secret Tree Skipped-Keys Window

Out-of-order application/handshake decryption is supported via a sliding window of skipped keys. By default, a per-leaf window of 128 generations is enabled.

Configure at group creation:

```python
from src.pymls.protocol.mls_group import MLSGroup

group = MLSGroup.create(
    group_id=b"group1",
    key_package=kp,
    crypto_provider=crypto,
    secret_tree_window_size=128  # Default
)
```

Older behavior (on-demand derivation without caching) is preserved for generations outside the window.

### Ratchet Tree Truncation

The ratchet tree truncates immediately when the rightmost leaf (and all trailing leaves) are blank after a removal (RFC 9420 §7.7). This reduces sparse tails and keeps the tree hash consistent with RFC expectations.

### Credentials

KeyPackage verification checks that the credential public key matches the leaf signature key. X.509 credential containers are supported:

```python
from src.pymls.crypto.x509 import X509Credential

# Verify X.509 certificate chain
cred = X509Credential.deserialize(cert_der)
cred.verify_chain(trust_roots)
```

Configure trust roots for chain validation:

```python
group._inner.set_trust_roots([trust_root1_der, trust_root2_der])
```

### X.509 Revocation Helpers

Revocation checks are pluggable. Batteries-included helpers are available:

```python
from src.pymls.crypto.x509_revocation import check_ocsp_end_entity, check_crl
from src.pymls.crypto.x509_policy import X509Policy, RevocationConfig

policy = X509Policy(
    revocation=RevocationConfig(
        enable_ocsp=True,
        enable_crl=True,
        # Use default fetchers (best-effort HTTP). For offline, provide custom fetchers.
        ocsp_checker=lambda cert_der: check_ocsp_end_entity(cert_der, issuer_der),
        crl_checker=lambda cert_der: check_crl(cert_der, issuer_der),
    )
)
```

By default, helpers fail-closed on network/responder errors (return revoked). To opt into fail-open behavior, pass `fail_open=True` to the helper functions.

## RFC 9420 Compliance

PyMLS aligns closely with RFC 9420 semantics:

- **Update Path Derivation**: Internode keys use top-down `path_secret` construction (RFC §7.4). A fresh `path_secret` is generated at the leaf and ratcheted upward with `DeriveSecret(..., "path")`. Each node key pair is deterministically derived from `DeriveSecret(path_secret, "node")`.

- **Deterministic KEM DeriveKeyPair**: Implements deterministic derivation for DHKEM X25519/X448 (with clamping) and for P-256/P-521 via modular reduction.

- **Proposal Ordering**: Commits partition and order proposals according to RFC §12.3:
  1. GroupContextExtensions
  2. Update
  3. Remove
  4. Add
  5. PreSharedKey
  
  ReInit proposals remain exclusive.

- **PSK Handling**: PSK proposals are bound via a commit binder and integrated into the epoch key schedule when present.

- **Transcript Bootstrap**: The interim transcript hash is initialized at group creation using an all-zero confirmation tag per RFC §11.

- **Parent Hash Validation**: Ratchet tree nodes include parent hash validation per RFC §7.9.

## Interop & Testing

### RFC 9420 Test Vectors

Run the RFC 9420 test vectors:

```bash
python -m src.pymls.interop.test_vectors_runner /path/to/vectors --suite 0x0001
```

Supported types include `key_schedule`, `tree_math`, `secret_tree`, `message_protection`, `welcome_groupinfo`, `tree_operations`, `messages`, and `encryption`. A JSON summary is printed.

### Interop CLI (RFC Wire)

The interop CLI exposes RFC-wire encode/decode helpers for handshake and application messages:

```bash
# Encode handshake (hex → base64 TLS presentation bytes)
python -m src.pymls.interop.cli wire encode-handshake <hex_plaintext>

# Decode handshake (base64 → hex)
python -m src.pymls.interop.cli wire decode-handshake <b64_wire>

# Encode application (hex → base64)
python -m src.pymls.interop.cli wire encode-application <hex_ciphertext>

# Decode application (base64 → hex)
python -m src.pymls.interop.cli wire decode-application <b64_wire>
```

This is intended to interoperate with other MLS implementations (e.g., OpenMLS). Wire helpers use the TLS presentation bytes described in RFC 9420 (§6–§7 for handshake, §9 for application).

## API Reference

### `src.pymls.Group`

High-level wrapper around `MLSGroup` providing an ergonomic API.

**Methods:**
- `create(group_id: bytes, key_package: KeyPackage, crypto: CryptoProvider) -> Group`
- `join_from_welcome(welcome: Welcome, hpke_private_key: bytes, crypto: CryptoProvider) -> Group`
- `add(key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext`
- `update(leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext`
- `remove(removed_index: int, signing_key: bytes) -> MLSPlaintext`
- `process_proposal(message: MLSPlaintext, sender_leaf_index: int) -> None`
- `commit(signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]`
- `apply_commit(message: MLSPlaintext, sender_leaf_index: int) -> None`
- `protect(application_data: bytes) -> MLSCiphertext`
- `unprotect(message: MLSCiphertext) -> tuple[int, bytes]`

**Properties:**
- `epoch: int` - Current group epoch
- `group_id: bytes` - Group identifier

### `src.pymls.DefaultCryptoProvider`

Concrete `CryptoProvider` implementation using the `cryptography` library.

**Constructor:**
- `DefaultCryptoProvider(suite_id: int = 0x0001)`

**Properties:**
- `supported_ciphersuites` - List of supported RFC suite ids
- `active_ciphersuite` - Currently selected `MlsCiphersuite`

**Methods:**
- `set_ciphersuite(suite_id: int) -> None` - Select a different ciphersuite

### `src.pymls.protocol.mls_group.MLSGroup`

Core protocol implementation. Most users should use `Group` instead.

**Advanced Methods:**
- `external_commit(key_package: KeyPackage, kem_public_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]`
- `process_external_commit(message: MLSPlaintext) -> None`
- `create_psk_proposal(psk_id: bytes, signing_key: bytes) -> MLSPlaintext`
- `reinit_group_to(new_group_id: bytes, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]`
- `get_resumption_psk() -> bytes`
- `set_strict_psk_binders(strict: bool) -> None`
- `set_trust_roots(trust_roots: list[bytes]) -> None`

## Migration from v0.1.x

### Breaking Changes

**Update Path Derivation**: Internode keys on an update path are now derived using a top-down `path_secret` construction (RFC §7.4). A single fresh `path_secret` is generated at the leaf and ratcheted upward with `DeriveSecret(..., "path")`. Each node key pair is deterministically derived from `DeriveSecret(path_secret, "node")`. This replaces the previous strategy of generating fresh key pairs and extracting secrets from private keys.

**Migration Guidance**: Groups created with previous versions that expect the legacy update-path derivation are not wire-compatible. Recreate groups or re-onboard members using new Welcomes.

### Enhancements

- Deterministic KEM DeriveKeyPair for all supported KEMs
- RFC §12.3 proposal ordering
- PSK binder integration
- Transcript bootstrap with zero confirmation tag
- Secret tree skipped-keys window (default: 128)
- Ratchet tree truncation per RFC §7.7

## Notes

- The library aims for correctness and clarity first. Recent updates removed MVP shortcuts and aligned with RFC 9420 semantics for group creation, commit ordering, parent hash, and Welcome tree encoding.
- External HPKE backend is provided by `cryptography` (fails fast if unavailable).
- Revocation helpers default to fail-closed unless explicitly configured to fail-open.
- The legacy DAVE protocol and opcodes were removed. This is a pure MLS library now.
- GroupContextExtensions proposals are accepted and ordered. Their data is merged into GroupInfo extensions for Welcomes; the GroupContext structure in this codebase remains minimal and does not store extensions explicitly.

## License

[Add your license information here]

## Contributing

[Add contributing guidelines here]

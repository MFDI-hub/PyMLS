# API Reference

This page reflects the public API exported by `src/rfc9420`.

## Main Imports

```python
from rfc9420 import (
    GroupConfig,
    MLSGroup,
    StagedCommit,
    PublicGroup,
    ProtocolMLSGroup,
    DefaultCryptoProvider,
    MemoryStorageProvider,
    DefaultRandProvider,
    get_commit_sender_leaf_index,
)
from rfc9420.api.session import MLSGroupSession
from rfc9420.api.policy import MLSAppPolicy, MLSOrchestrator, CommitIngestResult
```

## `GroupConfig`

Dataclass in `rfc9420.providers.config`:

- `crypto_provider` (required)
- `storage_provider` (required)
- `identity_provider` (optional)
- `rand_provider` (optional)
- `tree_backend_id` (`"array"` default)
- `secret_tree_window_size` (`128` default)
- `max_generation_gap` (`1000` default)
- `aead_limit_bytes` (optional)

Helper:

- `resolved_rand_provider() -> RandProviderProtocol`

## `MLSGroupSession`

Module: `rfc9420.api.session`

### Constructors

- `create_with_config(config, group_id, key_package, initial_extensions=b"")`
- `join_from_welcome_with_config(config, welcome, hpke_private_key, key_package=None)`
- `deserialize_with_config(config, data)`

### Handshake Methods (bytes I/O)

- `add_member(key_package, signing_key) -> bytes`
- `update_self(leaf_node, signing_key) -> bytes`
- `remove_member(removed_index, signing_key) -> bytes`
- `process_proposal(handshake_bytes, sender_leaf_index) -> None`
- `revoke_proposal(proposal_ref) -> None`
- `commit(signing_key, return_per_joiner_welcomes=False) -> tuple[bytes, list[Welcome]]`
- `apply_commit(handshake_bytes, sender_leaf_index) -> None`

### Application Methods

- `protect_application(plaintext, signing_key=None) -> bytes`
- `unprotect_application(ciphertext_bytes) -> tuple[int, bytes]`

### Export/Policy/Persistence

- `export_secret(label, context, length) -> bytes`
- `get_resumption_psk() -> bytes`
- `apply_policy(policy: MLSAppPolicy) -> None`
- `get_effective_policy() -> dict[str, int | None]`
- `serialize() -> bytes`
- `close() -> None`

### Properties

- `epoch`
- `group_id`
- `own_leaf_index`
- `member_count`

## `MLSGroup` (active group API)

Module: `rfc9420.group.mls_group.group` (re-exported from `rfc9420`).

### Constructors

- `create(config, group_id, key_package, initial_extensions=b"")`
- `join_from_welcome(config, welcome, hpke_private_key, key_package=None)`
- `from_bytes(config, data)`

### Commit/Proposal API

- `create_commit(signing_key, return_per_joiner_welcomes=False) -> StagedCommit`
- `apply_staged_commit(staged) -> None`
- `add(key_package, signing_key) -> MLSPlaintext`
- `update(leaf_node, signing_key) -> MLSPlaintext`
- `remove(removed_index, signing_key) -> MLSPlaintext`
- `process_proposal(message, sender_leaf_index, sender_type=1) -> None`
- `process_commit(message, sender_leaf_index=None) -> None`
- `process_commit_staged(message, sender_leaf_index=None) -> StagedCommit`
- `revoke_proposal(proposal_ref) -> None`

### Data/Exporter API

- `protect(application_data, signing_key=None) -> MLSCiphertext`
- `unprotect(message) -> tuple[int, bytes]`
- `export_secret(label, context, length) -> bytes`
- `get_resumption_psk() -> bytes`

### Properties

- `config`
- `epoch`
- `group_id`
- `own_leaf_index`
- `member_count`

## `StagedCommit`

Module: `rfc9420.group.mls_group.staged_commit`

Fields:

- `commit_message`
- `welcomes`
- `new_epoch_state`
- `prior_epoch`
- `group_id`
- `own_leaf_index`
- `tree_backend_id`

Method:

- `async merge(storage_provider) -> None`

## `PublicGroup`

Module: `rfc9420.group.public_group.group`

- `from_group_info(crypto_provider, group_info, tree_backend=DEFAULT_TREE_BACKEND)`
- `process_handshake(plaintext) -> None`
- `get_leaf_node(leaf_index) -> Any`

Properties: `group_id`, `epoch`, `member_count`.

## `get_commit_sender_leaf_index`

Utility from `rfc9420.group.mls_group.group` (re-exported):

```python
sender = get_commit_sender_leaf_index(commit_bytes)
session.apply_commit(commit_bytes, sender)
```

## Protocol Layer (`ProtocolMLSGroup`)

Low-level state machine exported as `ProtocolMLSGroup` from `rfc9420`.

Used for advanced/internal flows (external commit, PSK, re-init, custom validation).
Typical access in app code is through `session._group._inner` or `group._inner`.

## Backends

### Crypto / Random

- `DefaultCryptoProvider` (`rfc9420.backends.crypto.default_hpke`)
- `DefaultRandProvider` (`rfc9420.backends.crypto.default_rand`)

### Storage

- `MemoryStorageProvider` (`rfc9420.backends.storage.memory`)
- `SQLiteStorageProvider` (`rfc9420.backends.storage.sqlite`, imported lazily from `rfc9420.backends.storage`)

### Identity

- `X509IdentityProvider` (`rfc9420.backends.identity.x509_validator`)

## Policy API

`rfc9420.api.policy`:

- `MLSAppPolicy`: runtime and operational policy.
- `CommitIngestResult`: ingest status record.
- `MLSOrchestrator`: conflict handling + retention around `MLSGroupSession`.

## Tree Backend Constants

From `rfc9420`:

- `BACKEND_ARRAY`
- `BACKEND_PERFECT`
- `BACKEND_LINKED`
- `DEFAULT_TREE_BACKEND`

## Common Exceptions

Exported from `rfc9420`:

- `RFC9420Error` (base)
- `ProtocolError`, `CryptoError`, `StateError`, `MalformedMessageError`
- `InvalidWelcomeError`, `InvalidProposalError`, `InvalidCommitError`, `InvalidSignatureError`
- `CommitValidationError`
- `SameEpochCommitError`
- `PendingCommitError`, `PendingProposalError`, `NoPendingCommitError`
- `UseAfterEvictionError`
- `CannotDecryptOwnMessageError`
- `TLSDecodeError` (from `rfc9420.codec.tls`)



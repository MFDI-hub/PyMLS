# Architecture

This document maps the current code layout under `src/rfc9420` to runtime behavior.

## Package Structure

- `rfc9420.api`: high-level session and policy (`MLSGroupSession`, `MLSAppPolicy`, `MLSOrchestrator`).
- `rfc9420.group.mls_group`: active member API (`MLSGroup`, `StagedCommit`, `get_commit_sender_leaf_index`).
- `rfc9420.group.public_group`: passive observer API (`PublicGroup`).
- `rfc9420.group.mls_group.processing`: low-level protocol state machine (exported as `ProtocolMLSGroup`).
- `rfc9420.providers`: provider protocols + `GroupConfig`.
- `rfc9420.backends`: default providers (crypto/rand/storage/identity).
- `rfc9420.protocol.tree` and `rfc9420.protocol.schedule`: tree + key schedule internals.
- `rfc9420.messages`: wire/message/data structures.
- `rfc9420.interop`: wire adapters and CLI helpers.

## Layering

```text
Application
  -> MLSGroupSession (sync, bytes in/out)
      -> MLSGroup (staged commit lifecycle)
          -> ProtocolMLSGroup (state machine)
              -> RatchetTree / SecretTree / KeySchedule
              -> CryptoProviderProtocol + RandProviderProtocol
              -> StorageProviderProtocol (for staged merge)
```

## Staged Commit Lifecycle

The active API is intentionally split into persist and apply steps:

1. `staged = group.create_commit(signing_key)`
2. `await staged.merge(storage_provider)` (atomic persistence)
3. `group.apply_staged_commit(staged)` (in-memory transition)

`MLSGroupSession.commit(...)` wraps these three steps synchronously via an internal async runner.

## Provider Composition

`GroupConfig` contains:

- `crypto_provider` (required)
- `storage_provider` (required)
- `identity_provider` (optional)
- `rand_provider` (optional; defaults to `DefaultRandProvider`)
- `tree_backend_id` (`"array"` by default)
- runtime limits: `secret_tree_window_size`, `max_generation_gap`, `aead_limit_bytes`

Identity provider hooks are wired into group creation/join/restore through credential validator callbacks.

## Active vs Passive Group APIs

### `MLSGroup` (active)

- creates proposals and commits
- protects/unprotects application data
- owns pending proposal and pending commit state
- can process received commits mutating (`process_commit`) or staged (`process_commit_staged`)

### `PublicGroup` (passive)

- loads from `GroupInfo` (`from_group_info`)
- validates handshake signature/basic commit shape (`process_handshake`)
- tracks public tree view (`group_id`, `epoch`, `member_count`, `get_leaf_node`)
- does not maintain secret tree or key schedule

## Tree Backends

Tree backend IDs are exported from `rfc9420`:

- `BACKEND_ARRAY`
- `BACKEND_PERFECT`
- `BACKEND_LINKED`
- `DEFAULT_TREE_BACKEND`

Set backend through `GroupConfig(tree_backend_id=...)`.

## Policy Layer

`MLSAppPolicy` and `MLSOrchestrator` provide app-level controls on top of sessions:

- runtime limits (`secret_tree_window_size`, `max_generation_gap`, `aead_limit_bytes`)
- self-update scheduling (`update_interval_seconds`, `max_idle_before_update`)
- commit conflict strategy (`first_seen`, `highest_sender`, `deterministic_hash`)
- retention of resumption PSKs
- optional trust roots / X.509 policy passthrough

## Interop Layer

`rfc9420.interop.wire` provides presentation-layer helpers:

- `encode_handshake` / `decode_handshake`
- `encode_application` / `decode_application`

`rfc9420-interop` CLI wraps encoding/decoding for plaintext/ciphertext and base64 wire format conversion.

## Notes on Compatibility

`rfc9420.protocol.__init__` keeps compatibility aliases for old import paths under `rfc9420.protocol.*` by wiring modules from `rfc9420.protocol.tree.*`.


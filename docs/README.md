# RFC9420 Documentation

This folder documents the current provider-based API in `src/rfc9420`.

## Start Here

- [Getting Started](getting-started.md): install, configure providers, create/join a group.
- [Examples](examples.md): practical end-to-end snippets.
- [API Reference](api-reference.md): public classes, methods, and backends.
- [Advanced Features](advanced-features.md): external commit, PSK, re-init, policy, X.509.
- [Architecture](architecture.md): how `session`, `group`, `protocol`, `providers`, and `backends` fit together.

## What Changed In This Refactor

The package now centers on:

- `GroupConfig` (`rfc9420.providers.config`) to compose crypto/storage/identity/rand.
- `MLSGroup` (`rfc9420.group.mls_group`) with staged commits:
  1. `create_commit(...) -> StagedCommit`
  2. `await staged.merge(storage_provider)`
  3. `group.apply_staged_commit(staged)`
- `MLSGroupSession` (`rfc9420.api.session`) as a sync, byte-oriented wrapper around the staged flow.
- `PublicGroup` (`rfc9420.group.public_group`) for passive validation (no secrets).

## Recommended Reading Order

1. [Getting Started](getting-started.md)
2. [Examples](examples.md)
3. [API Reference](api-reference.md)
4. [Advanced Features](advanced-features.md)
5. [Architecture](architecture.md)

## Dev Commands

```bash
uv sync --dev
uv run ruff check .
uv run mypy src
uv run pytest -q
```

## References

- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)


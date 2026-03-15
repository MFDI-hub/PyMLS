# Advanced Features

Advanced workflows built on the current `MLSGroup` / `MLSGroupSession` architecture.

## 1) Staged Processing (Non-Mutating Commit Path)

Use this when you need to persist first, then apply:

```python
staged = group.process_commit_staged(commit_plaintext, sender_leaf_index=sender)
await staged.merge(group.config.storage_provider)
group.apply_staged_commit(staged)
```

This mirrors local commit creation:

```python
staged = group.create_commit(signing_key)
await staged.merge(group.config.storage_provider)
group.apply_staged_commit(staged)
```

## 2) External Commit (Low-Level API)

Available on the inner protocol group (`ProtocolMLSGroup`):

```python
commit_msg, welcomes = session._group._inner.external_commit(external_key_package, external_kem_public_key)
session._group._inner.process_external_commit(commit_msg)
```

Use this path for advanced interoperability workflows where a non-member joins via external commit semantics.

## 3) PSK Proposals

Create PSK proposal on `_inner`, then feed it through normal proposal/commit flow:

```python
from rfc9420.interop.wire import encode_handshake

psk_prop = session._group._inner.create_psk_proposal(psk_id=b"psk-1", signing_key=sig_sk)
session.process_proposal(encode_handshake(psk_prop), session.own_leaf_index)
commit_bytes, _ = session.commit(sig_sk)
```

Binder behavior tuning:

```python
session._group._inner.set_strict_psk_binders(False)
```

## 4) Re-Initialization

Re-init is exposed on `_inner`:

```python
from rfc9420.interop.wire import encode_handshake

commit_msg, welcomes = session._group._inner.reinit_group_to(b"next-group-id", signing_key=sig_sk)
commit_bytes = encode_handshake(commit_msg)
```

Other members process this commit normally (determine sender index then `apply_commit` / `process_commit`).

## 5) Runtime Policy + Orchestration

Policy defaults:

```python
from rfc9420.api.policy import MLSAppPolicy, MLSOrchestrator

policy = MLSAppPolicy.recommended()
session.apply_policy(policy)
orchestrator = MLSOrchestrator(session, policy)
```

Ingest incoming commit with policy conflict strategy:

```python
result = orchestrator.ingest_commit(commit_bytes, sender_leaf_index=sender)
print(result.status, result.applied, result.epoch, result.reason)
```

## 6) X.509 Support

### Identity Provider Path

Configure `GroupConfig(identity_provider=...)` with:

```python
from rfc9420.backends.identity import X509IdentityProvider

identity = X509IdentityProvider(trust_roots=[root_cert_der])
config = GroupConfig(
    crypto_provider=crypto,
    storage_provider=storage,
    identity_provider=identity,
)
```

### Credential Helpers

`rfc9420.messages.credentials` provides helper encodings:

```python
from rfc9420.messages.credentials import X509Credential

x = X509Credential.deserialize(serialized_bytes)
leaf_pub = x.verify_chain(trust_roots=[root_cert_der])
```

Note: MLS wire credentials used in key packages/leaf nodes are represented by `rfc9420.messages.data_structures.Credential`.

## 7) Secret Tree Runtime Tuning

Configure at group creation/load time through `GroupConfig`:

```python
cfg = GroupConfig(
    crypto_provider=crypto,
    storage_provider=storage,
    secret_tree_window_size=256,
    max_generation_gap=2000,
    aead_limit_bytes=32 * 1024 * 1024,
)
```

## 8) Interop Wire Helpers + CLI

Programmatic helpers:

- `rfc9420.interop.wire.encode_handshake` / `decode_handshake`
- `rfc9420.interop.wire.encode_application` / `decode_application`

CLI (`rfc9420-interop`) supports:

- `plaintext decode <hex>`
- `ciphertext decode <hex>`
- `wire encode-handshake <hex>`
- `wire decode-handshake <b64>`
- `wire encode-application <hex>`
- `wire decode-application <b64>`


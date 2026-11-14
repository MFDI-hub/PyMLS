# Getting Started with RFC9420

This guide uses the current provider-based API in `src/rfc9420`.

## Installation

### Prerequisites

- Python 3.9+
- `uv` (recommended)

```bash
pipx install uv
git clone https://github.com/MFDI-hub/PyMLS.git
cd PyMLS
uv sync
```

Quick check:

```bash
uv run python -c "from rfc9420 import GroupConfig, DefaultCryptoProvider, MemoryStorageProvider; from rfc9420.api.session import MLSGroupSession; print('ok')"
```

## Development Setup

```bash
uv sync --dev
uv run ruff check .
uv run mypy src
uv run pytest -q
```

## Core Concepts

- `GroupConfig`: binds providers and runtime settings.
- `MLSGroupSession`: sync/byte API (`create`, `join`, `add/update/remove`, `commit/apply`, protect/unprotect).
- `MLSGroup`: staged-commit API for advanced flows.
- `PublicGroup`: passive handshake validation without secrets.

## First Group (Two Members)

```python
import secrets

from rfc9420 import (
    GroupConfig,
    DefaultCryptoProvider,
    MemoryStorageProvider,
    MLSGroupSession,
)
from rfc9420.extensions.extensions import build_capabilities_data
from rfc9420.messages.data_structures import Credential, Signature
from rfc9420.messages.key_packages import KeyPackage, LeafNode

crypto = DefaultCryptoProvider()
storage = MemoryStorageProvider()
config = GroupConfig(crypto_provider=crypto, storage_provider=storage)


def make_member(identity: bytes):
    sig_sk = secrets.token_bytes(32)
    sig_pk = crypto.signature_public_from_private(sig_sk)
    _enc_sk, enc_pk = crypto.generate_key_pair()
    init_sk, init_pk = crypto.generate_key_pair()
    caps = build_capabilities_data(
        ciphersuite_ids=[crypto.active_ciphersuite.suite_id],
        supported_exts=[],
        include_grease=False,
    )
    cred = Credential(identity=identity, public_key=sig_pk)
    unsigned_leaf = LeafNode(
        encryption_key=enc_pk,
        signature_key=sig_pk,
        credential=cred,
        capabilities=caps,
        lifetime_not_before=0,
        lifetime_not_after=(1 << 64) - 1,
    )
    leaf_sig = crypto.sign_with_label(sig_sk, b"LeafNodeTBS", unsigned_leaf.tbs_serialize())
    leaf = LeafNode(
        encryption_key=enc_pk,
        signature_key=sig_pk,
        credential=cred,
        capabilities=caps,
        lifetime_not_before=0,
        lifetime_not_after=(1 << 64) - 1,
        signature=Signature(leaf_sig),
    )
    unsigned_kp = KeyPackage(init_key=init_pk, leaf_node=leaf)
    kp_sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", unsigned_kp.tbs_serialize())
    kp = KeyPackage(init_key=init_pk, leaf_node=leaf, signature=Signature(kp_sig))
    return kp, init_sk, sig_sk


kp_alice, _init_sk_alice, sig_sk_alice = make_member(b"alice")
alice = MLSGroupSession.create_with_config(config, b"my-group", kp_alice)

kp_bob, init_sk_bob, _sig_sk_bob = make_member(b"bob")
# add_member queues the Add on Alice. commit() covers that queue.
alice.add_member(kp_bob, sig_sk_alice)
_commit_bytes, welcomes = alice.commit(sig_sk_alice)

bob = MLSGroupSession.join_from_welcome_with_config(
    config, welcomes[0], init_sk_bob, key_package=kp_bob
)

ct = alice.protect_application(b"hello bob", sig_sk_alice)
sender, pt = bob.unprotect_application(ct)
assert (sender, pt) == (0, b"hello bob")
```

## Common Operations

### Self Update

```python
# update_self queues the proposal locally. Send new_hs to the other members.
new_hs = alice.update_self(new_leaf_node, sig_sk_alice)
commit_bytes, _ = alice.commit(sig_sk_alice)
```

### Remove Member

```python
rm_hs = alice.remove_member(removed_index=1, signing_key=sig_sk_alice)
commit_bytes, _ = alice.commit(sig_sk_alice)
```

### Persistence

```python
data = alice.serialize()
restored = MLSGroupSession.deserialize_with_config(config, data)
```

## Next Steps

- [Examples](examples.md)
- [API Reference](api-reference.md)
- [Advanced Features](advanced-features.md)
- [Architecture](architecture.md)


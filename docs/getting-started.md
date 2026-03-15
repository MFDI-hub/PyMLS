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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rfc9420 import (
    GroupConfig,
    DefaultCryptoProvider,
    MemoryStorageProvider,
)
from rfc9420.api.session import MLSGroupSession
from rfc9420.extensions.extensions import build_capabilities_data
from rfc9420.messages.key_packages import KeyPackage, LeafNode, LeafNodeSource
from rfc9420.messages.data_structures import Credential, Signature

crypto = DefaultCryptoProvider()
storage = MemoryStorageProvider()
config = GroupConfig(crypto_provider=crypto, storage_provider=storage)


def make_member(identity: bytes):
    kem_sk = X25519PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    init_sk = X25519PrivateKey.generate()  # for Welcome decrypt, distinct from leaf key
    init_pk = init_sk.public_key()

    sig_sk = Ed25519PrivateKey.generate()
    sig_pk = sig_sk.public_key()
    sig_pk_raw = sig_pk.public_bytes_raw()
    caps = build_capabilities_data(
        ciphersuite_ids=[crypto.active_ciphersuite.suite_id],
        supported_exts=[],
        include_grease=False,
    )
    cred = Credential(identity=identity, public_key=sig_pk_raw)
    leaf = LeafNode(
        encryption_key=kem_pk.public_bytes_raw(),
        signature_key=sig_pk_raw,
        credential=cred,
        capabilities=caps,
        leaf_node_source=LeafNodeSource.KEY_PACKAGE,
        parent_hash=b"",
    )
    kp_tbs = KeyPackage(leaf_node=leaf, init_key=init_pk.public_bytes_raw())
    sig = sig_sk.sign(kp_tbs.tbs_serialize())
    kp = KeyPackage(
        leaf_node=leaf,
        init_key=init_pk.public_bytes_raw(),
        signature=Signature(sig),
    )
    return kp, init_sk.private_bytes_raw(), sig_sk.private_bytes_raw()


# Alice creates group
kp_alice, init_sk_alice, sig_sk_alice = make_member(b"alice")
alice = MLSGroupSession.create_with_config(config, b"my-group", kp_alice)

# Bob key package
kp_bob, init_sk_bob, sig_sk_bob = make_member(b"bob")

# Alice proposes + commits Add(Bob)
alice.add_member(kp_bob, sig_sk_alice)
commit_bytes, welcomes = alice.commit(sig_sk_alice)

# Bob joins via Welcome (using init private key)
bob = MLSGroupSession.join_from_welcome_with_config(config, welcomes[0], init_sk_bob)

# App message
ct = alice.protect_application(b"hello bob")
sender, pt = bob.unprotect_application(ct)
print(sender, pt)
```

## Common Operations

### Self Update

```python
new_hs = alice.update_self(new_leaf_node, sig_sk_alice)
alice.process_proposal(new_hs, alice.own_leaf_index)
commit_bytes, _ = alice.commit(sig_sk_alice)
```

### Remove Member

```python
rm_hs = alice.remove_member(removed_index=1, signing_key=sig_sk_alice)
alice.process_proposal(rm_hs, alice.own_leaf_index)
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


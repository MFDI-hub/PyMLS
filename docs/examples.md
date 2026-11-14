# Examples

Practical snippets for the current API.

## Shared Setup

```python
import secrets

from rfc9420 import GroupConfig, DefaultCryptoProvider, MemoryStorageProvider
from rfc9420.extensions.extensions import build_capabilities_data
from rfc9420.messages.data_structures import Credential, Signature
from rfc9420.messages.key_packages import KeyPackage, LeafNode

crypto = DefaultCryptoProvider()
storage = MemoryStorageProvider()
config = GroupConfig(crypto_provider=crypto, storage_provider=storage)


def make_key_package(identity: bytes):
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
```

## Create + Join + Message

```python
from rfc9420.api.session import MLSGroupSession

kp_alice, init_alice, sig_alice = make_key_package(b"alice")
alice = MLSGroupSession.create_with_config(config, b"group-1", kp_alice)

kp_bob, init_bob, sig_bob = make_key_package(b"bob")
alice.add_member(kp_bob, sig_alice)
commit_bytes, welcomes = alice.commit(sig_alice)

bob = MLSGroupSession.join_from_welcome_with_config(
    config, welcomes[0], init_bob, key_package=kp_bob
)
ct = alice.protect_application(b"hello", sig_alice)
sender, pt = bob.unprotect_application(ct)
assert (sender, pt) == (0, b"hello")
```

## Process Commit From Another Member

```python
from rfc9420 import get_commit_sender_leaf_index

sender = get_commit_sender_leaf_index(commit_bytes)
some_other_member_session.apply_commit(commit_bytes, sender)
```

## Rotate Own Keys (Update Proposal)

```python
from rfc9420.messages.key_packages import LeafNode, LeafNodeSource

new_kp, _new_init, new_sig_sk = make_key_package(b"alice")
new_leaf = new_kp.leaf_node
new_leaf = LeafNode(
    encryption_key=new_leaf.encryption_key,
    signature_key=new_leaf.signature_key,
    credential=new_leaf.credential,
    capabilities=new_leaf.capabilities,
    leaf_node_source=LeafNodeSource.UPDATE,
)

hs = alice.update_self(new_leaf, sig_alice)
commit_bytes, _ = alice.commit(sig_alice)
sig_alice = new_sig_sk
```

## Remove Member

```python
hs = alice.remove_member(removed_index=1, signing_key=sig_alice)
commit_bytes, _ = alice.commit(sig_alice)
```

## Persist + Restore Session

```python
blob = alice.serialize()
alice_restored = MLSGroupSession.deserialize_with_config(config, blob)
```

## SQLite Storage Provider

```python
import secrets

from rfc9420.backends.storage import SQLiteStorageProvider
from rfc9420 import GroupConfig, DefaultCryptoProvider

cfg = GroupConfig(
    crypto_provider=DefaultCryptoProvider(),
    storage_provider=SQLiteStorageProvider(
        "mls_state.sqlite",
        at_rest_key=secrets.token_bytes(32),
    ),
)
```

## Error Handling Pattern

```python
from rfc9420 import InvalidCommitError, InvalidSignatureError, RFC9420Error

try:
    session.apply_commit(commit_bytes, sender_leaf_index=sender)
except (InvalidCommitError, InvalidSignatureError) as e:
    print(f"commit rejected: {e}")
except RFC9420Error as e:
    print(f"mls failure: {e}")
```

## Next

- [Getting Started](getting-started.md)
- [API Reference](api-reference.md)
- [Advanced Features](advanced-features.md)


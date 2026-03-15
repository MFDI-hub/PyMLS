# Examples

Practical snippets for the current API.

## Shared Setup

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rfc9420 import GroupConfig, DefaultCryptoProvider, MemoryStorageProvider
from rfc9420.extensions.extensions import build_capabilities_data
from rfc9420.messages.data_structures import Credential, Signature
from rfc9420.messages.key_packages import KeyPackage, LeafNode, LeafNodeSource

crypto = DefaultCryptoProvider()
storage = MemoryStorageProvider()
config = GroupConfig(crypto_provider=crypto, storage_provider=storage)


def make_key_package(identity: bytes):
    kem_sk = X25519PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    init_sk = X25519PrivateKey.generate()
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
    )
    kp_tbs = KeyPackage(leaf_node=leaf, init_key=init_pk.public_bytes_raw())
    kp_sig = Signature(sig_sk.sign(kp_tbs.tbs_serialize()))
    kp = KeyPackage(leaf_node=leaf, init_key=init_pk.public_bytes_raw(), signature=kp_sig)
    return kp, init_sk.private_bytes_raw(), sig_sk.private_bytes_raw()
```

## Create + Join + Message

```python
from rfc9420.api.session import MLSGroupSession

kp_alice, init_alice, sig_alice = make_key_package(b"alice")
alice = MLSGroupSession.create_with_config(config, b"group-1", kp_alice)

kp_bob, init_bob, sig_bob = make_key_package(b"bob")
alice.add_member(kp_bob, sig_alice)
commit_bytes, welcomes = alice.commit(sig_alice)

bob = MLSGroupSession.join_from_welcome_with_config(config, welcomes[0], init_bob)
ct = alice.protect_application(b"hello")
sender, pt = bob.unprotect_application(ct)
print(sender, pt)
```

## Process Commit From Another Member

```python
from rfc9420 import get_commit_sender_leaf_index

sender = get_commit_sender_leaf_index(commit_bytes)
some_other_member_session.apply_commit(commit_bytes, sender)
```

## Rotate Own Keys (Update Proposal)

```python
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
alice.process_proposal(hs, alice.own_leaf_index)
commit_bytes, _ = alice.commit(sig_alice)
sig_alice = new_sig_sk
```

## Remove Member

```python
hs = alice.remove_member(removed_index=1, signing_key=sig_alice)
alice.process_proposal(hs, alice.own_leaf_index)
commit_bytes, _ = alice.commit(sig_alice)
```

## Persist + Restore Session

```python
blob = alice.serialize()
alice_restored = MLSGroupSession.deserialize_with_config(config, blob)
```

## SQLite Storage Provider

```python
from rfc9420.backends.storage import SQLiteStorageProvider
from rfc9420 import GroupConfig, DefaultCryptoProvider

cfg = GroupConfig(
    crypto_provider=DefaultCryptoProvider(),
    storage_provider=SQLiteStorageProvider("mls_state.sqlite"),
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


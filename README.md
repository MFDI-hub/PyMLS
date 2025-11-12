# PyMLS
Pure Messaging Layer Security (MLS, RFC 9420) library in Python.

## Status
- Core wire types (`MLSPlaintext`, `MLSCiphertext`, `Welcome`, `GroupInfo`) implemented
- Group state machine for Add/Update/Remove, commit create/process
- Ratchet tree with parent-hash validation (MVP)
- Welcome processing with ratchet_tree extension
- Ergonomic API: `pymls.Group`

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

## Notes
- The library aims for correctness and clarity first. Recent updates added path-less commits, external commit processing, PSK binders, reinit context migration, and randomized application padding.
- The legacy DAVE protocol and opcodes were removed. This is a pure MLS library now.

## Advanced features
- Proposal-by-reference with commit validation
- EncryptedGroupSecrets in Welcome; ratchet_tree extension included
- External public key (EXTERNAL_PUB) published in GroupInfo; external commit (path-less) and processing without membership tag
- PSK proposals with RFC-style PSK binder carried in authenticated_data; strict verification by default
- Randomized application padding to 32-byte boundary
- Re-Initialization via path-less commit and context migration to new group_id
- Basic credential checks: KeyPackage credential public key must match signature key; X.509 container verification helper and trust roots configuration
- Resumption PSK export via `Group.get_resumption_psk()` (through protocol)

Planned next: broaden RFC vector coverage and interop CLI, full X.509 policy and revocation, extended negative/fuzz tests, and API stabilization timeline.

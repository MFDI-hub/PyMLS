# PyMLS
Pure Messaging Layer Security (MLS, RFC 9420) library in Python.

## Status
- Core wire types (`MLSPlaintext`, `MLSCiphertext`, `Welcome`, `GroupInfo`) implemented
- Group state machine for Add/Update/Remove, commit create/process (RFC-aligned ordering)
- Ratchet tree with RFC-style parent-hash validation
- Welcome processing with full ratchet_tree extension (internal nodes included)
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
- The library aims for correctness and clarity first. Recent updates removed MVP shortcuts and aligned with RFC 9420 semantics for group creation, commit ordering, parent hash, and Welcome tree encoding. External HPKE backend is now provided by `cryptography` (fails fast if unavailable). Revocation helpers default to fail-closed unless explicitly configured to fail-open.

## Interop Test Vectors
Run the RFC 9420 test vectors with:

```bash
python -m src.pymls.interop.test_vectors_runner /path/to/vectors --suite 0x0001
```

Supported types include key_schedule, tree_math, secret_tree, message_protection, welcome_groupinfo, tree_operations, messages, and encryption. A JSON summary is printed.
- The legacy DAVE protocol and opcodes were removed. This is a pure MLS library now.

## Setup with uv

This project uses a pyproject.toml (PEP 621). Prefer uv for dependency management:

```bash
pipx install uv  # once
uv sync --dev

# Lint, type-check, test
uv run ruff check .
uv run mypy src
uv run pytest -q
```

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

### Secret tree skipped-keys window

Out-of-order application/handshake decryption is supported via a sliding window of skipped keys. By default, a per-leaf window of 128 generations is enabled.

- Configure at group level: `MLSGroup(..., secret_tree_window_size=128)`
- Programmatic construction: `SecretTree(encryption_secret, crypto, n_leaves, window_size=128)`

Older behavior (on-demand derivation without caching) is preserved for generations outside the window, so existing applications remain compatible.

### Ratchet tree truncation (normative §7.7)

The ratchet tree now truncates immediately when the rightmost leaf (and all trailing leaves) are blank after a removal. This reduces sparse tails and keeps the tree hash consistent with RFC expectations.

## Interop CLI (RFC wire)

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

## X.509 revocation helpers (optional)

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

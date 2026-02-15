# Architecture

This document describes the internal architecture of RFC9420 and how the various components work together.

## Overview

RFC9420 is organized into several main modules:

- **`rfc9420.mls`**: High-level API (`Group` class)
- **`rfc9420.protocol`**: Core protocol implementation (`MLSGroup`, data structures, messages)
- **`rfc9420.crypto`**: Cryptographic operations and providers
- **`rfc9420.codec`**: TLS encoding/decoding
- **`rfc9420.extensions`**: Extension handling
- **`rfc9420.interop`**: Interoperability tools and test vectors

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Application Layer                     │
│  (Uses Group API for MLS operations)                     │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  Group (High-Level API)                  │
│  - Ergonomic wrapper around MLSGroup                     │
│  - Simplified interface for common operations           │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              MLSGroup (Protocol Layer)                   │
│  - Ratchet tree management                               │
│  - Key schedule derivation                               │
│  - Proposal processing                                    │
│  - Commit creation/processing                            │
│  - Message protection                                    │
└──────┬──────────────┬──────────────┬─────────────────────┘
       │              │              │
┌──────▼──────┐ ┌─────▼──────┐ ┌────▼──────┐
│ RatchetTree │ │KeySchedule │ │SecretTree │
│             │ │            │ │           │
│ - Tree ops  │ │ - Secrets  │ │ - Keys    │
│ - Parent    │ │ - Branches │ │ - Window  │
│   hash      │ │ - PSK      │ │           │
└─────────────┘ └────────────┘ └───────────┘
       │              │              │
       └──────────────┼──────────────┘
                      │
            ┌─────────▼─────────┐
            │  CryptoProvider    │
            │  (Abstract)        │
            └─────────┬─────────┘
                      │
            ┌─────────▼─────────┐
            │DefaultCryptoProvider│
            │  (cryptography)     │
            └─────────────────────┘
```

## Core Components

### Group (High-Level API)

The `Group` class provides an ergonomic interface for MLS operations. It wraps `MLSGroup` and provides:
- Simplified method names
- Automatic error conversion
- Cleaner API surface

**Location:** `src/rfc9420/mls/group.py`

### MLSGroup (Protocol Implementation)

The `MLSGroup` class implements the core MLS protocol state machine:

- **Ratchet Tree**: Binary tree of HPKE key pairs
- **Key Schedule**: Epoch secret and branch secret derivation
- **Secret Tree**: Per-sender encryption keys
- **Transcript Hashes**: Interim and confirmed transcript hashes
- **Proposal Queue**: Pending proposals awaiting commit
- **Proposal Cache**: Map of proposal references to proposals

**Location:** `src/rfc9420/protocol/mls_group.py`

### Ratchet Tree

The ratchet tree is a binary tree structure where:
- Leaf nodes represent group members
- Internal nodes contain HPKE key pairs
- Parent hashes bind nodes to their parents (RFC §7.9)

**Key Operations:**
- `add_leaf()`: Add a new member
- `remove_leaf()`: Remove a member
- `update_leaf()`: Update a member's keys
- `calculate_tree_hash()`: Compute tree hash for GroupContext

**Location:** `src/rfc9420/protocol/ratchet_tree.py`

### Key Schedule

The key schedule derives all secrets for an epoch:

- **Epoch Secret**: Root secret for the epoch
- **Application Secret**: For application message encryption
- **Handshake Secret**: For handshake message encryption
- **Exporter Secret**: For external key material export
- **Confirmation Key**: For confirmation tag computation
- **Membership Key**: For membership tag computation
- **Resumption PSK**: For group resumption

**Location:** `src/rfc9420/protocol/key_schedule.py`

### Secret Tree

The secret tree derives per-sender encryption keys:

- **Application Keys**: For encrypting application messages
- **Handshake Keys**: For encrypting handshake messages
- **Skipped-Keys Window**: Caches keys for out-of-order decryption

**Location:** `src/rfc9420/protocol/secret_tree.py`

### CryptoProvider

Abstract interface for cryptographic operations:

- Key derivation (HKDF)
- Hashing
- AEAD encryption/decryption
- Digital signatures
- HPKE operations
- Key generation

**Concrete Implementation:** `DefaultCryptoProvider` uses the `cryptography` library.

**Location:** 
- Interface: `src/rfc9420/crypto/crypto_provider.py`
- Implementation: `src/rfc9420/crypto/default_crypto_provider.py`

## Message Flow

### Proposal Flow

```
Member A                    Member B
   │                           │
   ├─ Create Proposal ────────┤
   │                           │
   ├─ Sign & Send ────────────►│
   │                           │
   │                    ┌──────▼──────┐
   │                    │ Verify Sig   │
   │                    │ Cache Prop   │
   │                    │ Queue Prop   │
   │                    └─────────────┘
   │                           │
   │                    ┌──────▼──────┐
   │                    │ Process Prop │
   │                    └─────────────┘
```

### Commit Flow

```
Member A                    Member B
   │                           │
   ├─ Create Commit ──────────┤
   │  - Order proposals        │
   │  - Generate UpdatePath    │
   │  - Compute PSK binder     │
   │  - Sign commit            │
   │                           │
   ├─ Send Commit ────────────►│
   │                           │
   │                    ┌──────▼──────┐
   │                    │ Verify Sig  │
   │                    │ Validate    │
   │                    │ Apply Ops   │
   │                    │ Update Tree │
   │                    │ Derive Keys │
   │                    └─────────────┘
```

### Application Message Flow

```
Sender                       Receiver
   │                            │
   ├─ Protect Message ─────────┤
   │  - Get sender key          │
   │  - Encrypt content         │
   │  - Add sender data         │
   │                            │
   ├─ Send Ciphertext ─────────►│
   │                            │
   │                     ┌──────▼──────┐
   │                     │ Unprotect   │
   │                     │ - Decrypt   │
   │                     │ - Verify    │
   │                     │ - Extract   │
   │                     └─────────────┘
```

## Key Derivation

### Update Path Derivation (RFC §7.4)

```
Leaf Node
   │
   ├─ Generate path_secret
   │
   ├─ DeriveSecret(path_secret, "path") ──► Parent path_secret
   │
   ├─ DeriveSecret(path_secret, "node") ──► Node key pair
   │
   └─ Repeat for each node on path to root
```

### Key Schedule Derivation (RFC §9)

```
Joiner Secret / Epoch Secret
   │
   ├─ ExpandWithLabel(..., "epoch", GroupContext) ──► Epoch Secret
   │
   ├─ DeriveSecret(epoch_secret, "application") ──► Application Secret
   ├─ DeriveSecret(epoch_secret, "handshake") ────► Handshake Secret
   ├─ DeriveSecret(epoch_secret, "exporter") ─────► Exporter Secret
   ├─ DeriveSecret(epoch_secret, "confirm") ─────► Confirmation Key
   ├─ DeriveSecret(epoch_secret, "membership") ──► Membership Key
   └─ DeriveSecret(epoch_secret, "resumption") ───► Resumption PSK
```

## Proposal Ordering (RFC §12.3)

Commits order proposals as follows:

1. **GroupContextExtensions**: Group-level extensions
2. **Update**: Member key updates
3. **Remove**: Member removals
4. **Add**: Member additions
5. **PreSharedKey**: PSK proposals

**Note:** ReInit proposals are exclusive (cannot be combined with others).

## Security Considerations

### Forward Secrecy

- Each epoch derives fresh secrets
- Old epoch secrets are not retained
- Update paths refresh keys

### Post-Compromise Security

- Update proposals refresh compromised keys
- New epochs invalidate old keys
- Ratchet tree structure ensures key independence

### Authentication

- All proposals and commits are signed
- Membership tags prevent unauthorized messages
- PSK binders prevent replay attacks

## Extension Points

### Custom CryptoProvider

Implement `CryptoProvider` interface for custom cryptographic backends:

```python
class CustomCryptoProvider(CryptoProvider):
    def hash(self, data: bytes) -> bytes:
        # Custom implementation
        pass
    # ... implement all abstract methods
```

### X.509 Policy

Customize X.509 credential validation:

```python
policy = X509Policy(
    revocation=RevocationConfig(...),
    # ... other policy options
)
group._inner.set_x509_policy(policy)
```

## Testing

### Test Vectors

RFC9420 includes support for RFC 9420 test vectors:

```bash
python -m src.rfc9420.interop.test_vectors_runner /path/to/vectors --suite 0x0001
```

### Unit Tests

Tests are organized by component:
- `test_group_flow.py`: Group operations
- `test_ratchet_tree_*.py`: Ratchet tree operations
- `test_key_schedule.py`: Key derivation
- `test_crypto_provider.py`: Cryptographic operations

## Performance Considerations

### Secret Tree Window

- Larger window: Faster out-of-order decryption, more memory
- Smaller window: Less memory, slower out-of-order decryption
- Default: 128 generations per leaf

### Proposal Batching

- Batch multiple proposals in a single commit
- Reduces overhead of multiple commits
- Improves efficiency for bulk operations

### Tree Truncation

- Automatic truncation reduces tree size
- Keeps tree hash consistent
- Reduces memory usage for large groups

## Future Enhancements

Potential areas for improvement:

1. **Full X.509 Support**: Complete EKU/keyUsage checks
2. **Tree Sync**: Efficient tree synchronization protocols
3. **Application Acknowledgments**: APP_ACK proposal support
4. **Group Context Extensions**: Full extension support
5. **Performance Optimizations**: Caching, batching improvements

## References

- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) - Messaging Layer Security
- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) - HPKE: Hybrid Public Key Encryption
- [API Reference](api-reference.md) - RFC9420 API documentation


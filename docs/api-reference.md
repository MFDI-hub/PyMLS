# API Reference

Complete API reference for RFC9420.

## Core Classes

### `Group`

High-level API for MLS group operations. This is the recommended interface for most users.

#### Class Methods

##### `Group.create(group_id: bytes, key_package: KeyPackage, crypto: CryptoProvider, secret_tree_window_size: int = 128, max_generation_gap: int = 1000, aead_limit_bytes: int | None = None, tree_backend: str = DEFAULT_TREE_BACKEND) -> Group`

Create a new MLS group with an initial member.

**Parameters:**
- `group_id` (bytes): Application-chosen identifier for the group
- `key_package` (KeyPackage): KeyPackage of the initial member
- `crypto` (CryptoProvider): CryptoProvider instance
- `secret_tree_window_size` (int): Secret tree skipped-keys window size (default 128)
- `max_generation_gap` (int): Max generation gap for out-of-order decryption (default 1000)
- `aead_limit_bytes` (int | None): Optional AEAD usage limit per key
- `tree_backend` (str): Ratchet tree backend (`BACKEND_ARRAY`, `BACKEND_PERFECT`, `BACKEND_LINKED`, or default)

**Returns:**
- `Group`: New group instance with epoch 0

**Example:**
```python
group = Group.create(b"my_group", key_package, crypto)
```

##### `Group.join_from_welcome(welcome: Welcome, hpke_private_key: bytes, crypto: CryptoProvider, secret_tree_window_size: int = 128, max_generation_gap: int = 1000, aead_limit_bytes: int | None = None, tree_backend: str = DEFAULT_TREE_BACKEND) -> Group`

Join an existing group using a Welcome message.

**Parameters:**
- `welcome` (Welcome): Welcome message received out-of-band
- `hpke_private_key` (bytes): HPKE private key (init key) for decrypting EncryptedGroupSecrets
- `crypto` (CryptoProvider): CryptoProvider instance
- Optional: `secret_tree_window_size`, `max_generation_gap`, `aead_limit_bytes`, `tree_backend` (same as `create`)

**Returns:**
- `Group`: New group instance initialized from Welcome

**Raises:**
- `InvalidWelcomeError`: If no EncryptedGroupSecrets can be opened or GroupInfo is invalid
- `InvalidSignatureError`: If GroupInfo signature verification fails

**Example:**
```python
group = Group.join_from_welcome(welcome, hpke_private_key, crypto)
```

#### Instance Methods

##### `add(key_package: KeyPackage, signing_key: bytes) -> MLSPlaintext`

Create an Add proposal to add a new member.

**Parameters:**
- `key_package` (KeyPackage): KeyPackage of the member to add
- `signing_key` (bytes): Private signing key

**Returns:**
- `MLSPlaintext`: Proposal message

##### `update(leaf_node: LeafNode, signing_key: bytes) -> MLSPlaintext`

Create an Update proposal to refresh the sender's leaf node.

**Parameters:**
- `leaf_node` (LeafNode): New LeafNode with updated keys
- `signing_key` (bytes): Private signing key

**Returns:**
- `MLSPlaintext`: Proposal message

##### `remove(removed_index: int, signing_key: bytes) -> MLSPlaintext`

Create a Remove proposal to remove a member.

**Parameters:**
- `removed_index` (int): Leaf index of member to remove
- `signing_key` (bytes): Private signing key

**Returns:**
- `MLSPlaintext`: Proposal message

##### `process_proposal(message: MLSPlaintext, sender_leaf_index: int, sender_type: SenderType | int = SenderType.MEMBER) -> None`

Verify and enqueue a received proposal.

**Parameters:**
- `message` (MLSPlaintext): Proposal message
- `sender_leaf_index` (int): Leaf index of sender
- `sender_type` (SenderType | int): `SenderType.MEMBER` (1), `SenderType.EXTERNAL` (2), etc. Use `SenderType` enum.

**Raises:**
- `InvalidProposalError`: If verification fails or sender is invalid
- `InvalidSignatureError`: If signature or membership tag verification fails

##### `commit(signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]`

Create a commit with all pending proposals.

**Parameters:**
- `signing_key` (bytes): Private signing key

**Returns:**
- `tuple[MLSPlaintext, list[Welcome]]`: Commit message and Welcome messages for new members

##### `apply_commit(message: MLSPlaintext, sender_leaf_index: int | None = None) -> None`

Verify and apply a received commit.

**Parameters:**
- `message` (MLSPlaintext): Commit message
- `sender_leaf_index` (int | None): Leaf index of commit sender. If `None`, read from message (use `get_commit_sender_leaf_index(message.serialize())`).

**Raises:**
- `InvalidCommitError`: If commit validation fails or sender is invalid

##### `protect(application_data: bytes) -> MLSCiphertext`

Encrypt application data.

**Parameters:**
- `application_data` (bytes): Plaintext to encrypt

**Returns:**
- `MLSCiphertext`: Encrypted message

**Raises:**
- `RFC9420Error`: If group not initialized or commit pending

##### `unprotect(message: MLSCiphertext) -> tuple[int, bytes]`

Decrypt application ciphertext.

**Parameters:**
- `message` (MLSCiphertext): Encrypted message

**Returns:**
- `tuple[int, bytes]`: (sender_leaf_index, plaintext)

**Raises:**
- `RFC9420Error`: If decryption fails

#### Properties

##### `epoch: int`

Current group epoch (read-only).

##### `group_id: bytes`

Group identifier (read-only).

##### `own_leaf_index: int`

Local member's leaf index (read-only).

##### `member_count: int`

Number of members (leaves) in the group (read-only).

#### Additional Methods

##### `get_commit_sender_leaf_index(commit_bytes: bytes) -> int`

Return the leaf index of the commit sender from serialized commit plaintext. Use so callers do not need to know message layout.

**Parameters:** `commit_bytes`: Serialized MLSPlaintext of a commit.

**Returns:** Sender's leaf index.

**Raises:** `InvalidCommitError`: If message is not a commit or deserialization fails.

##### `export_secret(label: bytes, context: bytes, length: int) -> bytes`

Export external keying material using the MLS exporter.

##### `get_resumption_psk() -> bytes`

Return resumption PSK for the current epoch.

##### `to_bytes() -> bytes`

Serialize group state for persistence.

##### `Group.from_bytes(data: bytes, crypto: CryptoProvider, tree_backend: str = DEFAULT_TREE_BACKEND) -> Group`

Deserialize group state into a Group instance.

##### `configure_runtime_policy(*, secret_tree_window_size: int | None = None, max_generation_gap: int | None = None, aead_limit_bytes: int | None = None) -> None`

Set runtime limits for SecretTree receive/send enforcement.

##### `get_runtime_policy() -> dict[str, int | None]`

Return currently active runtime-limit values.

##### `set_trust_roots(roots_pem: list[bytes]) -> None`

Configure trust anchors for X.509 credential chain validation.

##### `set_x509_policy(policy) -> None`

Configure X.509 policy checks applied after chain validation.

##### `iter_members()`

Iterate over `(leaf_index, identity)` for each member.

##### `close() -> None`

Best-effort wipe of in-memory secrets.

---

### `get_commit_sender_leaf_index`

Standalone function to get committer leaf index from serialized commit:

```python
from rfc9420 import get_commit_sender_leaf_index
sender = get_commit_sender_leaf_index(commit.serialize())
group.apply_commit(commit, sender_leaf_index=sender)  # or omit for auto
```

### `SenderType`

Enum for sender type in proposals/commits: `SenderType.MEMBER` (1), `SenderType.EXTERNAL` (2), etc. Use with `process_proposal(..., sender_type=SenderType.MEMBER)`.

---

### `DefaultCryptoProvider`

Concrete CryptoProvider implementation using the cryptography library.

#### Constructor

##### `DefaultCryptoProvider(suite_id: int = 0x0001)`

Initialize with a ciphersuite.

**Parameters:**
- `suite_id` (int): RFC 9420 ciphersuite ID (default: 0x0001)

**Raises:**
- `UnsupportedCipherSuiteError`: If ciphersuite not supported

**Example:**
```python
crypto = DefaultCryptoProvider(suite_id=0x0001)  # X25519 + AES-128-GCM + Ed25519
```

#### Properties

##### `supported_ciphersuites`

List of supported RFC ciphersuite IDs.

##### `active_ciphersuite: MlsCiphersuite`

Currently selected ciphersuite.

#### Methods

##### `set_ciphersuite(suite_id: int) -> None`

Select a different ciphersuite.

**Parameters:**
- `suite_id` (int): RFC 9420 ciphersuite ID

---

### `MLSGroup`

Low-level protocol implementation. Most users should use `Group` instead.

#### Advanced Methods

##### `external_commit(key_package: KeyPackage, kem_public_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]`

Create an external commit (path-less) for adding a member.

**Parameters:**
- `key_package` (KeyPackage): KeyPackage of member to add
- `kem_public_key` (bytes): External HPKE public key

**Returns:**
- `tuple[MLSPlaintext, list[Welcome]]`: Commit and Welcome messages

**Raises:**
- `ConfigurationError`: If no external private key configured

##### `process_external_commit(message: MLSPlaintext) -> None`

Process an external commit.

**Parameters:**
- `message` (MLSPlaintext): External commit message

**Raises:**
- `ConfigurationError`: If no external public key configured
- `CommitValidationError`: If validation fails

##### `create_psk_proposal(psk_id: bytes, signing_key: bytes) -> MLSPlaintext`

Create a Pre-Shared Key proposal.

**Parameters:**
- `psk_id` (bytes): PSK identifier
- `signing_key` (bytes): Private signing key

**Returns:**
- `MLSPlaintext`: PSK proposal

##### `reinit_group_to(new_group_id: bytes, signing_key: bytes) -> tuple[MLSPlaintext, list[Welcome]]`

Create a re-initialization commit.

**Parameters:**
- `new_group_id` (bytes): New group identifier
- `signing_key` (bytes): Private signing key

**Returns:**
- `tuple[MLSPlaintext, list[Welcome]]`: Commit and Welcome messages

##### `get_resumption_psk() -> bytes`

Export current resumption PSK.

**Returns:**
- `bytes`: Resumption PSK

**Raises:**
- `RFC9420Error`: If group not initialized

##### `set_strict_psk_binders(strict: bool) -> None`

Configure PSK binder verification strictness.

**Parameters:**
- `strict` (bool): If True, require PSK binders (default: True)

##### `set_trust_roots(trust_roots: list[bytes]) -> None`

Configure X.509 trust roots.

**Parameters:**
- `trust_roots` (list[bytes]): List of DER-encoded trust root certificates

---

## Data Structures

### `KeyPackage`

Container for a member's public keys and credentials.

**Fields:**
- `leaf_node` (LeafNode): Leaf node with keys and credential
- `signature` (Signature): Signature over the leaf node
- `init_key` (bytes): HPKE public key for Welcome decryption (must differ from `leaf_node.encryption_key`)
- `version`, `cipher_suite`, `extensions` (optional)

### `LeafNode`

Leaf node in the ratchet tree (RFC 9420 §7.2).

**Fields:**
- `encryption_key` (bytes): HPKE public key
- `signature_key` (bytes): Signature public key
- `credential` (Credential | None): Member credential
- `capabilities` (bytes): Capabilities extension data
- `leaf_node_source` (LeafNodeSource): KEY_PACKAGE, UPDATE, or COMMIT
- `parent_hash` (bytes): Parent hash for UPDATE/COMMIT
- `lifetime_not_before`, `lifetime_not_after` (int): For KEY_PACKAGE
- `extensions` (list): Extension list

### `Credential`

Member credential binding identity to public key.

**Fields:**
- `identity` (bytes): Member identity
- `public_key` (bytes): Public key

### `Welcome`

Welcome message for new members.

**Fields:**
- `version` (MLSVersion): Protocol version
- `cipher_suite` (CipherSuite): Group ciphersuite
- `secrets` (list[EncryptedGroupSecrets]): Encrypted group secrets
- `encrypted_group_info` (bytes): Encrypted GroupInfo

### `MLSPlaintext`

Handshake message (proposals and commits).

**Fields:**
- `group_id` (bytes): Group identifier
- `epoch` (int): Epoch number
- `content_type` (ContentType): Message type
- `content` (bytes): Message content
- `signature` (bytes): Signature
- `membership_tag` (bytes | None): Membership tag

### `MLSCiphertext`

Application message.

**Fields:**
- `group_id` (bytes): Group identifier
- `epoch` (int): Epoch number
- `content_type` (ContentType): Always APPLICATION
- `encrypted_sender_data` (bytes): Encrypted sender info
- `ciphertext` (bytes): Encrypted content

---

## Ciphersuites

### Supported Ciphersuites

| ID   | Name                                                    | KEM        | KDF        | AEAD            | Signature |
|------|--------------------------------------------------------|------------|------------|-----------------|-----------|
| 0x0001 | MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519        | X25519     | SHA-256    | AES-128-GCM     | Ed25519   |
| 0x0002 | MLS_128_DHKEMP256_AES128GCM_SHA256_P256              | P-256      | SHA-256    | AES-128-GCM     | ECDSA P-256 |
| 0x0003 | MLS_128_DHKEMX25519_CHACHAPOLY_SHA256_Ed25519       | X25519     | SHA-256    | ChaCha20Poly1305| Ed25519   |
| 0x0004 | MLS_128_DHKEMP256_CHACHAPOLY_SHA256_P256            | P-256      | SHA-256    | ChaCha20Poly1305| ECDSA P-256 |
| 0x0005 | MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448            | X448       | SHA-512    | AES-256-GCM     | Ed448     |
| 0x0006 | MLS_256_DHKEMP521_AES256GCM_SHA512_P521              | P-521      | SHA-512    | AES-256-GCM     | ECDSA P-521 |
| 0x0007 | MLS_256_DHKEMX448_CHACHAPOLY_SHA512_Ed448           | X448       | SHA-512    | ChaCha20Poly1305| Ed448     |
| 0x0008 | MLS_256_DHKEMP521_CHACHAPOLY_SHA512_P521            | P-521      | SHA-512    | ChaCha20Poly1305| ECDSA P-521 |

### Helper Functions

##### `get_ciphersuite_by_id(suite_id: int) -> Optional[MlsCiphersuite]`

Look up ciphersuite by RFC ID.

##### `get_ciphersuite_by_name(name: str) -> Optional[MlsCiphersuite]`

Look up ciphersuite by canonical name.

##### `all_ciphersuites() -> Iterable[MlsCiphersuite]`

Get all registered ciphersuites.

---

## Session and Policy API

### `MLSGroupSession`

Synchronous high-level session wrapper around `Group`. Provides byte-oriented handshake and application I/O. Create via `MLSGroupSession.create(group_id, key_package, crypto, policy=None, tree_backend=...)` or `MLSGroupSession.join_from_welcome(welcome, hpke_private_key, crypto, policy=None, tree_backend=...)`. Methods include `add_member`, `update_self`, `remove_member`, `process_proposal`, `commit`, `apply_commit`, `protect_application`, `unprotect_application`, and exporter-based key derivation.

### `MLSAppPolicy`

Dataclass for application policy: `update_interval_seconds`, `max_idle_before_update`, `max_resumption_epochs`, `secret_tree_window_size`, `max_generation_gap`, `aead_limit_bytes`, `conflict_resolution_strategy`, `enforce_epoch_lock`, `x509_mode`, `trust_roots`, `x509_policy`. Use `MLSAppPolicy.recommended()` for balanced defaults.

### `MLSOrchestrator`

Policy-aware helper for commit sequencing and retention. Construct with `MLSOrchestrator(session, policy)`. Methods: `note_activity`, `should_rotate_now`, `record_self_update`, `record_resumption_psk`, `list_resumption_psks`, and commit ingest helpers.

### `CommitIngestResult`

Result of commit ingest: `status`, `applied`, `epoch`, `reason`.

## Ratchet Tree Backends

- `BACKEND_ARRAY`, `BACKEND_PERFECT`, `BACKEND_LINKED`: Tree implementation names.
- `DEFAULT_TREE_BACKEND`: Default backend name. Pass as `tree_backend` to `Group.create` / `Group.join_from_welcome` / `Group.from_bytes`.

## Exceptions

### `RFC9420Error`

Base exception for all RFC9420 errors.

### `InvalidWelcomeError`

Raised when a Welcome message cannot be processed (e.g. no secret opens, invalid GroupInfo).

### `InvalidProposalError`

Raised when a proposal fails verification or validation.

### `InvalidCommitError`

Raised when a commit fails verification or validation.

### `CommitValidationError`

Raised internally when commit or referenced proposals fail validation.

### `InvalidSignatureError`

Raised when signature or membership tag verification fails.

### `UnsupportedCipherSuiteError`

Raised when an unsupported ciphersuite is requested.

### `ConfigurationError`

Raised when configuration is invalid or missing.

### `EpochMismatchError`

Raised when an operation targets an unexpected or stale epoch.

### `CredentialRevocationError`

Raised when a credential is determined to be revoked (CRL/OCSP).

### `CredentialValidationError`

Raised for credential/chain validation failures unrelated to revocation.


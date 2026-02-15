# Advanced Features

This guide covers advanced features of RFC9420 including external commits, Pre-Shared Keys (PSKs), re-initialization, and X.509 credential handling.

## External Commits

External commits allow parties that are not currently group members to join a group without requiring a Welcome message. This is useful for scenarios where you want to allow external parties to join directly.

### How External Commits Work

1. The group publishes an `EXTERNAL_PUB` extension in `GroupInfo`
2. An external party creates an external commit with their KeyPackage
3. The commit is signed with the group's external key (no membership tag required)
4. The commit includes an ExternalInit proposal and an Add proposal
5. The commit is path-less (no UpdatePath) since the external party has no existing leaf

### Example: External Commit

```python
from rfc9420.protocol.mls_group import MLSGroup

# On the group side: Create external commit
external_kp = create_key_package(...)
external_kem_pk = generate_kem_public_key()

commit, welcomes = group._inner.external_commit(external_kp, external_kem_pk)

# Send commit to group members
# Group members process it:
group._inner.process_external_commit(commit)
```

### Processing External Commits

```python
# Group members receive and process external commit
group._inner.process_external_commit(external_commit_message)
```

**Note:** External commits are verified using the group's external public key, not membership tags.

## Pre-Shared Keys (PSKs)

PSKs allow groups to incorporate shared secrets into the key schedule. This is useful for:
- Resuming previous group states
- Adding external authentication
- Implementing application-specific security policies

### Creating PSK Proposals

```python
# Create a PSK proposal
psk_id = b"my_psk_identifier"
psk_proposal = group._inner.create_psk_proposal(psk_id, signing_key)

# Process the proposal
group.process_proposal(psk_proposal, sender_index)

# Create commit (PSK binder will be automatically computed)
commit, welcomes = group.commit(signing_key)
```

### PSK Binders

When a commit includes PSK proposals, a PSK binder is automatically computed and included in the `authenticated_data` field. The binder binds the PSK to the commit content, preventing replay attacks.

**PSK Binder Verification:**
- By default, PSK binder verification is strict (required)
- Configure with `group._inner.set_strict_psk_binders(False)` to relax verification

### Resumption PSKs

Each epoch generates a resumption PSK that can be used to resume the group state:

```python
# Export resumption PSK
resumption_psk = group._inner.get_resumption_psk()

# Store for later use
# ... later, use PSK in a new group or epoch
```

## Re-Initialization

Re-initialization allows migrating a group to a new `group_id` and resetting the epoch. This is useful for:
- Group lifecycle management
- Implementing group archival
- Creating group snapshots

### Creating a ReInit Commit

```python
new_group_id = b"new_group_identifier"
commit, welcomes = group._inner.reinit_group_to(new_group_id, signing_key)

# Process the commit
group.apply_commit(commit, sender_index)
# Group now has new_group_id and epoch reset to 0
```

### ReInit Behavior

- The group migrates to the new `group_id`
- Epoch resets to 0
- All members remain in the group
- Ratchet tree structure is preserved

## Secret Tree Skipped-Keys Window

RFC9420 supports out-of-order message decryption via a sliding window of skipped keys. This allows decrypting messages that arrive out of order without requiring on-demand key derivation for every skipped generation.

### Configuration

```python
from rfc9420.protocol.mls_group import MLSGroup

# Create group with custom window size
group = MLSGroup.create(
    group_id=b"group1",
    key_package=kp,
    crypto_provider=crypto,
    secret_tree_window_size=256  # Default is 128
)
```

### How It Works

- Messages within the window (e.g., 128 generations) are cached for fast decryption
- Messages outside the window use on-demand derivation (slower but still works)
- Window size is per-leaf, so each sender has their own window

**Trade-offs:**
- Larger window: Faster out-of-order decryption, more memory usage
- Smaller window: Less memory, slower out-of-order decryption

## Ratchet Tree Truncation

The ratchet tree automatically truncates when the rightmost leaf (and all trailing leaves) are blank after a removal. This reduces sparse tails and keeps the tree hash consistent with RFC 9420 §7.7.

**Behavior:**
- Truncation happens automatically after Remove operations
- Tree hash remains consistent with RFC expectations
- No manual intervention required

## X.509 Credentials

RFC9420 supports X.509 certificate credentials for group members.

### Basic X.509 Support

```python
from rfc9420.crypto.x509 import X509Credential

# Deserialize X.509 credential
cred = X509Credential.deserialize(cert_der)

# Verify certificate chain
trust_roots = [root_cert1_der, root_cert2_der]
cred.verify_chain(trust_roots)
```

### Configuring Trust Roots

```python
# Set trust roots for group
group._inner.set_trust_roots([trust_root1_der, trust_root2_der])
```

### X.509 Revocation

RFC9420 provides helpers for checking certificate revocation via OCSP and CRL:

```python
from rfc9420.crypto.x509_revocation import check_ocsp_end_entity, check_crl
from rfc9420.crypto.x509_policy import X509Policy, RevocationConfig

# Configure revocation policy
policy = X509Policy(
    revocation=RevocationConfig(
        enable_ocsp=True,
        enable_crl=True,
        ocsp_checker=lambda cert_der: check_ocsp_end_entity(
            cert_der, issuer_der, fail_open=False
        ),
        crl_checker=lambda cert_der: check_crl(
            cert_der, issuer_der, fail_open=False
        ),
    )
)

# Apply policy to group
group._inner.set_x509_policy(policy)
```

### Revocation Behavior

- **Fail-closed (default)**: Network/responder errors return "revoked"
- **Fail-open**: Network/responder errors return "not revoked"
- Configure with `fail_open=True` parameter

## Proposal-by-Reference

Proposals are cached using RFC 9420 §5.2 proposal references. Commits reference cached proposals rather than including them inline.

**Benefits:**
- Smaller commit messages
- Efficient proposal validation
- Supports distributed proposal distribution

**How It Works:**
1. Proposals are cached on receipt with a proposal reference
2. Commits include `proposal_refs` instead of inline proposals
3. Commit processing validates that referenced proposals match commit content

## GroupContext Extensions

GroupContext extensions allow groups to include custom data in the group context. Extension data is merged into GroupInfo extensions for Welcomes.

**Note:** The GroupContext structure in RFC9420 remains minimal and does not store extensions explicitly. Extension data is handled via GroupInfo extensions.

## Best Practices

### Key Rotation

Regularly update your leaf node keys:

```python
# Generate new keys periodically
new_leaf = create_updated_leaf_node(...)
update_prop = group.update(new_leaf, signing_key)
group.process_proposal(update_prop, your_index)
commit, _ = group.commit(signing_key)
```

### Error Handling

Always handle exceptions appropriately:

```python
try:
    group.apply_commit(commit, sender_index)
except ValueError as e:
    # Commit validation failed
    print(f"Commit rejected: {e}")
except InvalidSignatureError:
    # Signature verification failed
    print("Invalid signature")
```

### State Persistence

Persist group state between sessions:

```python
# Save group state
group_state = {
    'group_id': group.group_id,
    'epoch': group.epoch,
    # ... other state
}

# Restore group state
# (Implementation depends on your storage backend)
```

### Performance Considerations

- Use appropriate `secret_tree_window_size` based on your use case
- Batch proposals when possible to reduce commit frequency
- Consider using external commits for high-frequency joins

## Security Considerations

1. **Key Management**: Store private keys securely (use key management systems)
2. **Credential Verification**: Always verify credentials before accepting members
3. **Revocation**: Implement revocation checking for X.509 credentials
4. **PSK Security**: Use cryptographically strong PSKs
5. **External Commits**: Verify external commits carefully (they bypass normal membership checks)

## Further Reading

- [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) - Complete MLS specification
- [API Reference](api-reference.md) - Detailed API documentation
- [Examples](examples.md) - Code examples for common scenarios


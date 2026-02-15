# Examples

This document provides practical examples for common RFC9420 use cases.

## Table of Contents

1. [Basic Group Operations](#basic-group-operations)
2. [Multi-Member Group](#multi-member-group)
3. [Key Rotation](#key-rotation)
4. [Member Removal](#member-removal)
5. [External Commit](#external-commit)
6. [PSK Usage](#psk-usage)
7. [Re-Initialization](#re-initialization)
8. [X.509 Credentials](#x509-credentials)
9. [Error Handling](#error-handling)
10. [State Persistence](#state-persistence)

## Basic Group Operations

### Creating and Joining a Group

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from src.rfc9420 import Group, DefaultCryptoProvider
from src.rfc9420.protocol.key_packages import KeyPackage, LeafNode
from src.rfc9420.protocol.data_structures import Credential, Signature

crypto = DefaultCryptoProvider()

def create_key_package(identity: bytes):
    """Create a key package for a new member."""
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

# Create group
kp_alice, kem_sk_alice, sig_sk_alice = create_key_package(b"alice")
group_alice = Group.create(b"my_group", kp_alice, crypto)

# Add member
kp_bob, kem_sk_bob, sig_sk_bob = create_key_package(b"bob")
prop = group_alice.add(kp_bob, sig_sk_alice)
group_alice.process_proposal(prop, 0)
commit, welcomes = group_alice.commit(sig_sk_alice)

# Bob joins
group_bob = Group.join_from_welcome(welcomes[0], kem_sk_bob, crypto)

# Send message
ciphertext = group_alice.protect(b"Hello!")
sender, plaintext = group_bob.unprotect(ciphertext)
print(f"From {sender}: {plaintext}")
```

## Multi-Member Group

### Adding Multiple Members

```python
# Create group with Alice
kp_alice, kem_sk_alice, sig_sk_alice = create_key_package(b"alice")
group = Group.create(b"group", kp_alice, crypto)

# Add Bob
kp_bob, kem_sk_bob, sig_sk_bob = create_key_package(b"bob")
prop_bob = group.add(kp_bob, sig_sk_alice)
group.process_proposal(prop_bob, 0)

# Add Charlie
kp_charlie, kem_sk_charlie, sig_sk_charlie = create_key_package(b"charlie")
prop_charlie = group.add(kp_charlie, sig_sk_alice)
group.process_proposal(prop_charlie, 0)

# Commit both additions
commit, welcomes = group.commit(sig_sk_alice)
# welcomes[0] is for Bob, welcomes[1] is for Charlie

# Bob and Charlie join
group_bob = Group.join_from_welcome(welcomes[0], kem_sk_bob, crypto)
group_charlie = Group.join_from_welcome(welcomes[1], kem_sk_charlie, crypto)
```

## Key Rotation

### Updating Your Keys

```python
def rotate_keys(group: Group, old_sig_sk: bytes, identity: bytes):
    """Rotate encryption and signature keys."""
    # Generate new keys
    new_kem_sk = X25519PrivateKey.generate()
    new_kem_pk = new_kem_sk.public_key()
    new_sig_sk = Ed25519PrivateKey.generate()
    new_sig_pk = new_sig_sk.public_key()
    
    # Create new leaf node
    cred = Credential(identity=identity, public_key=new_sig_pk.public_bytes_raw())
    new_leaf = LeafNode(
        encryption_key=new_kem_pk.public_bytes_raw(),
        signature_key=new_sig_pk.public_bytes_raw(),
        credential=cred,
        capabilities=b"",
        parent_hash=b"",
    )
    
    # Create update proposal
    update_prop = group.update(new_leaf, old_sig_sk)
    group.process_proposal(update_prop, your_leaf_index)
    commit, _ = group.commit(old_sig_sk)
    
    return new_kem_sk, new_sig_sk, commit

# Rotate keys
new_kem_sk, new_sig_sk, commit = rotate_keys(group, sig_sk_alice, b"alice")
# Process commit on other members' groups
```

## Member Removal

### Removing a Member

```python
def remove_member(group: Group, member_index: int, signing_key: bytes):
    """Remove a member from the group."""
    remove_prop = group.remove(member_index, signing_key)
    group.process_proposal(remove_prop, your_leaf_index)
    commit, _ = group.commit(signing_key)
    return commit

# Remove member at index 1
commit = remove_member(group, 1, sig_sk_alice)
# Other members process the commit
group_bob.apply_commit(commit, 0)
group_charlie.apply_commit(commit, 0)
```

## External Commit

### Joining via External Commit

```python
from src.rfc9420.protocol.mls_group import MLSGroup

# External party creates key package
external_kp, external_kem_sk, external_sig_sk = create_key_package(b"external")
external_kem_pk = X25519PrivateKey.from_private_bytes(external_kem_sk).public_key()

# Group creates external commit
commit, welcomes = group._inner.external_commit(
    external_kp,
    external_kem_pk.public_bytes_raw()
)

# Group members process external commit
group._inner.process_external_commit(commit)

# External party joins (if Welcome is provided, or processes commit directly)
# Note: External commits may not always produce Welcome messages
```

## PSK Usage

### Using Pre-Shared Keys

```python
def add_psk_to_group(group: Group, psk_id: bytes, signing_key: bytes):
    """Add a PSK to the group."""
    psk_proposal = group._inner.create_psk_proposal(psk_id, signing_key)
    group.process_proposal(psk_proposal, your_leaf_index)
    commit, welcomes = group.commit(signing_key)
    return commit

# Add PSK
psk_id = b"shared_secret_12345"
commit = add_psk_to_group(group, psk_id, sig_sk_alice)

# Export resumption PSK
resumption_psk = group._inner.get_resumption_psk()
print(f"Resumption PSK: {resumption_psk.hex()}")
```

## Re-Initialization

### Reinitializing a Group

```python
def reinit_group(group: Group, new_group_id: bytes, signing_key: bytes):
    """Reinitialize group with new ID."""
    commit, welcomes = group._inner.reinit_group_to(new_group_id, signing_key)
    return commit, welcomes

# Reinitialize
new_group_id = b"new_group_v2"
commit, welcomes = reinit_group(group, new_group_id, sig_sk_alice)

# All members process reinit commit
group_bob.apply_commit(commit, 0)
# Group now has new_group_id and epoch reset to 0
```

## X.509 Credentials

### Using X.509 Certificates

```python
from src.rfc9420.crypto.x509 import X509Credential

def create_x509_key_package(cert_der: bytes, private_key_der: bytes):
    """Create key package with X.509 credential."""
    # Load certificate
    cred = X509Credential.deserialize(cert_der)
    
    # Verify chain
    trust_roots = [load_trust_root1(), load_trust_root2()]
    cred.verify_chain(trust_roots)
    
    # Create key package with X.509 credential
    # ... (similar to basic key package creation)
    pass

# Configure trust roots
group._inner.set_trust_roots([trust_root1_der, trust_root2_der])
```

### Revocation Checking

```python
from src.rfc9420.crypto.x509_revocation import check_ocsp_end_entity, check_crl
from src.rfc9420.crypto.x509_policy import X509Policy, RevocationConfig

def create_revocation_policy():
    """Create X.509 revocation policy."""
    return X509Policy(
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

# Apply policy
policy = create_revocation_policy()
group._inner.set_x509_policy(policy)
```

## Error Handling

### Comprehensive Error Handling

```python
from src.rfc9420.mls.exceptions import (
    CommitValidationError,
    InvalidSignatureError,
    RFC9420Error,
)

def safe_apply_commit(group: Group, commit: MLSPlaintext, sender: int):
    """Safely apply a commit with error handling."""
    try:
        group.apply_commit(commit, sender)
        print("Commit applied successfully")
    except ValueError as e:
        # Commit validation failed
        print(f"Commit validation error: {e}")
        # Handle invalid commit
    except InvalidSignatureError:
        print("Invalid signature")
        # Handle signature error
    except RFC9420Error as e:
        print(f"MLS error: {e}")
        # Handle general MLS error
    except Exception as e:
        print(f"Unexpected error: {e}")
        # Handle unexpected errors

# Use safe wrapper
safe_apply_commit(group, commit, sender_index)
```

## State Persistence

### Saving and Restoring Group State

```python
import json
import pickle

class GroupStateManager:
    """Manage group state persistence."""
    
    @staticmethod
    def save_group_state(group: Group, filepath: str):
        """Save group state to file."""
        state = {
            'group_id': group.group_id.hex(),
            'epoch': group.epoch,
            # Add other state as needed
        }
        with open(filepath, 'w') as f:
            json.dump(state, f)
    
    @staticmethod
    def load_group_state(filepath: str):
        """Load group state from file."""
        with open(filepath, 'r') as f:
            return json.load(f)

# Save state
GroupStateManager.save_group_state(group, 'group_state.json')

# Load state
state = GroupStateManager.load_group_state('group_state.json')
print(f"Group ID: {bytes.fromhex(state['group_id'])}")
print(f"Epoch: {state['epoch']}")
```

## Complete Example: Chat Application

```python
class MLSChatGroup:
    """Simple chat group wrapper."""
    
    def __init__(self, identity: bytes, group_id: bytes):
        self.identity = identity
        self.crypto = DefaultCryptoProvider()
        kp, self.kem_sk, self.sig_sk = create_key_package(identity)
        self.group = Group.create(group_id, kp, self.crypto)
        self.members = {0: identity}
    
    def add_member(self, member_kp: KeyPackage, member_identity: bytes):
        """Add a new member."""
        prop = self.group.add(member_kp, self.sig_sk)
        self.group.process_proposal(prop, 0)
        commit, welcomes = self.group.commit(self.sig_sk)
        self.members[len(self.members)] = member_identity
        return commit, welcomes
    
    def send_message(self, message: str):
        """Send a message to the group."""
        return self.group.protect(message.encode())
    
    def receive_message(self, ciphertext: MLSCiphertext):
        """Receive and decrypt a message."""
        sender, plaintext = self.group.unprotect(ciphertext)
        sender_identity = self.members.get(sender, b"unknown")
        return sender_identity, plaintext.decode()

# Usage
alice_chat = MLSChatGroup(b"alice", b"chat_group")
bob_kp, bob_kem_sk, bob_sig_sk = create_key_package(b"bob")
commit, welcomes = alice_chat.add_member(bob_kp, b"bob")

bob_chat = Group.join_from_welcome(welcomes[0], bob_kem_sk, alice_chat.crypto)

# Alice sends message
msg = alice_chat.send_message("Hello, Bob!")

# Bob receives
sender, text = bob_chat.receive_message(msg)
print(f"{sender.decode()}: {text}")
```

## Further Reading

- [Getting Started](getting-started.md) - Basic usage guide
- [API Reference](api-reference.md) - Complete API documentation
- [Advanced Features](advanced-features.md) - Advanced usage patterns


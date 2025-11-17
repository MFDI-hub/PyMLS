# Getting Started with PyMLS

This guide will help you get started with PyMLS, a pure Python implementation of the Messaging Layer Security (MLS) protocol as specified in RFC 9420.

## Installation

PyMLS uses `pyproject.toml` (PEP 621) for dependency management. We recommend using `uv` for fast and reliable dependency resolution.

### Prerequisites

- Python 3.8 or higher
- `uv` package manager (optional but recommended)

### Install uv

```bash
pipx install uv  # Install uv globally
```

### Install PyMLS

```bash
# Clone the repository
git clone https://github.com/yourusername/PyMLS.git
cd PyMLS

# Install dependencies
uv sync --dev

# Verify installation
uv run python -c "from src.pymls import Group, DefaultCryptoProvider; print('PyMLS installed successfully!')"
```

### Development Setup

For development, install with dev dependencies:

```bash
uv sync --dev

# Run linting
uv run ruff check .

# Run type checking
uv run mypy src

# Run tests
uv run pytest -q
```

## Basic Concepts

### MLS Groups

An MLS group is a collection of members who can send encrypted messages to each other. Each group has:
- A unique `group_id`
- An `epoch` number that increments with each state change
- A ratchet tree for managing member keys
- A key schedule for deriving encryption keys

### Key Packages

A KeyPackage contains a member's public keys and credentials. It's used when adding new members to a group.

### Proposals and Commits

- **Proposals**: Requests to change group state (add member, remove member, update keys, etc.)
- **Commits**: Collections of proposals that are applied atomically to advance the epoch

## Your First MLS Group

Let's create a simple two-member group:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.pymls import Group, DefaultCryptoProvider
from src.pymls.protocol.key_packages import KeyPackage, LeafNode
from src.pymls.protocol.data_structures import Credential, Signature

# Initialize crypto provider
crypto = DefaultCryptoProvider()  # Uses MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

def make_member(identity: bytes):
    """Create a new member with keys and credentials."""
    # Generate HPKE key pair for encryption
    kem_sk = X25519PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    
    # Generate signature key pair
    sig_sk = Ed25519PrivateKey.generate()
    sig_pk = sig_sk.public_key()
    
    # Create credential
    cred = Credential(identity=identity, public_key=sig_pk.public_bytes_raw())
    
    # Create leaf node
    leaf = LeafNode(
        encryption_key=kem_pk.public_bytes_raw(),
        signature_key=sig_pk.public_bytes_raw(),
        credential=cred,
        capabilities=b"",
        parent_hash=b"",
    )
    
    # Sign the leaf node
    sig = sig_sk.sign(leaf.serialize())
    kp = KeyPackage(leaf, Signature(sig))
    
    return kp, kem_sk.private_bytes_raw(), sig_sk.private_bytes_raw()

# Create first member (Alice)
kp_alice, kem_sk_alice, sig_sk_alice = make_member(b"alice")
group_alice = Group.create(b"my_group", kp_alice, crypto)

# Create second member (Bob)
kp_bob, kem_sk_bob, sig_sk_bob = make_member(b"bob")

# Alice adds Bob to the group
prop = group_alice.add(kp_bob, sig_sk_alice)
group_alice.process_proposal(prop, 0)  # Process the proposal
commit_pt, welcomes = group_alice.commit(sig_sk_alice)  # Create commit

# Bob joins using the Welcome message
group_bob = Group.join_from_welcome(welcomes[0], kem_sk_bob, crypto)

# Alice sends a message
ciphertext = group_alice.protect(b"Hello, Bob!")

# Bob receives and decrypts
sender, plaintext = group_bob.unprotect(ciphertext)
print(f"Message from sender {sender}: {plaintext}")  # Message from sender 0: b'Hello, Bob!'
```

## Understanding the Flow

1. **Group Creation**: Alice creates a group with herself as the initial member
2. **Add Proposal**: Alice creates an Add proposal for Bob
3. **Proposal Processing**: Alice processes her own proposal (in real apps, proposals come from other members)
4. **Commit**: Alice creates a commit that includes the Add proposal
5. **Welcome**: The commit generates a Welcome message for Bob
6. **Join**: Bob uses the Welcome message to join the group
7. **Messaging**: Both members can now send encrypted messages

## Next Steps

- Read the [API Reference](api-reference.md) for detailed method documentation
- Explore [Advanced Features](advanced-features.md) for PSKs, external commits, and more
- Check out [Examples](examples.md) for more complex use cases
- Review [Architecture](architecture.md) to understand the internals

## Common Patterns

### Updating Your Keys

```python
# Generate new keys
new_kem_sk = X25519PrivateKey.generate()
new_kem_pk = new_kem_sk.public_key()
new_sig_sk = Ed25519PrivateKey.generate()
new_sig_pk = new_sig_sk.public_key()

# Create new leaf node
new_leaf = LeafNode(
    encryption_key=new_kem_pk.public_bytes_raw(),
    signature_key=new_sig_pk.public_bytes_raw(),
    credential=cred,
    capabilities=b"",
    parent_hash=b"",
)

# Create update proposal
update_prop = group.update(new_leaf, sig_sk)
group.process_proposal(update_prop, your_leaf_index)
commit, _ = group.commit(sig_sk)
```

### Removing a Member

```python
# Create remove proposal
remove_prop = group.remove(member_leaf_index, sig_sk)
group.process_proposal(remove_prop, your_leaf_index)
commit, _ = group.commit(sig_sk)
```

## Troubleshooting

### Common Issues

**Import Errors**: Make sure you're using `src.pymls` as the import path:
```python
from src.pymls import Group  # Correct
from pymls import Group      # Incorrect (unless installed as package)
```

**HPKE Not Available**: Ensure you have cryptography >= 41.0.0:
```bash
uv pip install --upgrade cryptography
```

**Key Package Verification Fails**: Ensure the credential public key matches the signature key in the leaf node.

## Getting Help

- Check the [API Reference](api-reference.md) for method details
- Review [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) for protocol details
- Open an issue on GitHub for bugs or feature requests


"""RFC9420: MLS (Messaging Layer Security) implementation with provider-based architecture.

Public API (breaking from pre-1.0):

- GroupConfig, MLSGroup, StagedCommit: config-driven active member API; create_commit
  returns StagedCommit; call staged_commit.merge(storage) then group.apply_staged_commit(staged).
- PublicGroup: passive observer (no secrets); from_group_info, process_handshake.
- get_commit_sender_leaf_index(commit_bytes): committer leaf index from serialized commit.
- DefaultCryptoProvider, MemoryStorageProvider: batteries-included backends.
- ProtocolMLSGroup: low-level protocol state machine (for tests/advanced use).
"""
from .providers import (
    GroupConfig,
    CryptoProviderProtocol,
    RandProviderProtocol,
    StorageProviderProtocol,
    IdentityProviderProtocol,
    GroupEpochState,
)
from .group.mls_group import MLSGroup, StagedCommit, get_commit_sender_leaf_index
from .group.public_group import PublicGroup
from .backends.crypto.default_hpke import DefaultCryptoProvider
from .backends.storage.memory import MemoryStorageProvider
from .backends.crypto.default_rand import DefaultRandProvider
from .group.mls_group.processing import MLSGroup as ProtocolMLSGroup
from .messages.data_structures import CipherSuite, MLSVersion, Sender, SenderType
from .crypto.ciphersuites import CipherSuiteId
from .protocol.tree.ratchet_tree_backend import (
    BACKEND_ARRAY,
    BACKEND_PERFECT,
    BACKEND_LINKED,
    DEFAULT_TREE_BACKEND,
)
from .mls.exceptions import (
    CannotDecryptOwnMessageError,
    RFC9420Error,
    ProtocolError,
    CryptoError,
    StateError,
    MalformedMessageError,
    CommitValidationError,
    InvalidWelcomeError,
    InvalidProposalError,
    InvalidCommitError,
    InvalidSignatureError,
    SameEpochCommitError,
    PendingCommitError,
    PendingProposalError,
    NoPendingCommitError,
    UseAfterEvictionError,
)
from .codec.tls import TLSDecodeError

__all__ = [
    "GroupConfig",
    "CryptoProviderProtocol",
    "RandProviderProtocol",
    "StorageProviderProtocol",
    "IdentityProviderProtocol",
    "GroupEpochState",
    "MLSGroup",
    "StagedCommit",
    "get_commit_sender_leaf_index",
    "PublicGroup",
    "DefaultCryptoProvider",
    "MemoryStorageProvider",
    "DefaultRandProvider",
    "ProtocolMLSGroup",
    "CipherSuite",
    "CipherSuiteId",
    "MLSVersion",
    "Sender",
    "SenderType",
    "BACKEND_ARRAY",
    "BACKEND_PERFECT",
    "BACKEND_LINKED",
    "DEFAULT_TREE_BACKEND",
    "CannotDecryptOwnMessageError",
    "RFC9420Error",
    "ProtocolError",
    "CryptoError",
    "StateError",
    "MalformedMessageError",
    "CommitValidationError",
    "InvalidWelcomeError",
    "InvalidProposalError",
    "InvalidCommitError",
    "InvalidSignatureError",
    "SameEpochCommitError",
    "PendingCommitError",
    "PendingProposalError",
    "NoPendingCommitError",
    "UseAfterEvictionError",
    "TLSDecodeError",
]

__version__ = "0.9.0"

"""RFC9420: A minimal, pragmatic MLS (Messaging Layer Security) implementation for Python.

This package provides a pure Python implementation of RFC 9420 (Messaging Layer Security).
It includes core protocol types, cryptographic operations, and a high-level Group API
for managing MLS groups.

Public API (prefer these so you do not depend on internals):
    - Group: create/join, add/update/remove proposals, commit, apply_commit, protect/unprotect.
      Use group.member_count, group.own_leaf_index, group.iter_members() instead of _inner.
    - get_commit_sender_leaf_index(commit_bytes): get committer leaf index from serialized commit.
    - SenderType: use SenderType.MEMBER, SenderType.EXTERNAL instead of magic integers.
    - Exceptions: InvalidWelcomeError, InvalidProposalError, InvalidCommitError for precise handling.

Example:
    >>> from rfc9420 import Group, DefaultCryptoProvider, get_commit_sender_leaf_index, SenderType
    >>> crypto = DefaultCryptoProvider()
    >>> group = Group.create(b"group1", key_package, crypto)
    >>> group.process_proposal(msg, sender_leaf_index=0, sender_type=SenderType.MEMBER)
    >>> sender = get_commit_sender_leaf_index(commit.serialize())
    >>> group.apply_commit(commit)  # sender optional, read from message
"""

from .mls.group import Group, get_commit_sender_leaf_index
from .crypto.default_crypto_provider import DefaultCryptoProvider
from .protocol.mls_group import MLSGroup
from .protocol.data_structures import CipherSuite, MLSVersion, Sender, SenderType
from .crypto.ciphersuites import CipherSuiteId
from .api import MLSGroupSession, MLSAppPolicy, MLSOrchestrator, CommitIngestResult
from .protocol.ratchet_tree_backend import (
    BACKEND_ARRAY,
    BACKEND_PERFECT,
    BACKEND_LINKED,
    DEFAULT_TREE_BACKEND,
)
from .mls.exceptions import (
    CannotDecryptOwnMessageError,
    RFC9420Error,
    CommitValidationError,
    InvalidWelcomeError,
    InvalidProposalError,
    InvalidCommitError,
    InvalidSignatureError,
    SameEpochCommitError,
)


__all__ = [
    "Group",
    "get_commit_sender_leaf_index",
    "DefaultCryptoProvider",
    "MLSGroup",
    "MLSGroupSession",
    "MLSAppPolicy",
    "MLSOrchestrator",
    "CommitIngestResult",
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
    "CommitValidationError",
    "InvalidWelcomeError",
    "InvalidProposalError",
    "InvalidCommitError",
    "InvalidSignatureError",
    "SameEpochCommitError",
]

__version__ = "0.8.0"

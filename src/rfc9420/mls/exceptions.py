"""Custom exception hierarchy for RFC 9420 (MLS) operations.

All protocol and crypto errors inherit from RFC9420Error.
Consumers can catch specific types (InvalidWelcomeError, InvalidProposalError,
InvalidCommitError) without relying on generic Exception or internal errors.
"""
class RFC9420Error(Exception):
    """Base class for all RFC9420 errors."""


class ProtocolError(RFC9420Error):
    """Protocol rule violations and semantic validation failures."""


class CryptoError(RFC9420Error):
    """Cryptographic verification/decryption/signing failures."""


class StateError(RFC9420Error):
    """Invalid operation for current MLS group lifecycle state."""


class MalformedMessageError(RFC9420Error):
    """Malformed wire data or invalid serialization inputs."""


class CommitValidationError(ProtocolError):
    """Raised when a Commit or its referenced proposals fail validation (internal)."""


class InvalidWelcomeError(ProtocolError):
    """Raised when a Welcome message cannot be processed (e.g. no secret opens, invalid GroupInfo)."""


class InvalidProposalError(ProtocolError):
    """Raised when a proposal fails verification or validation."""


class InvalidCommitError(ProtocolError):
    """Raised when a commit fails verification or validation."""


class InvalidSignatureError(CryptoError):
    """Raised when signature or membership tag verification fails."""


class EpochMismatchError(ProtocolError):
    """Raised when an operation targets an unexpected or stale epoch."""


class SameEpochCommitError(ProtocolError):
    """Raised when a commit is received for the current epoch (RFC 9420 §14).

    Applications MUST implement conflict resolution when multiple commits
    exist for the same epoch; catch this error to detect and resolve.
    """


class UnsupportedCipherSuiteError(RFC9420Error):
    """Raised when an unsupported cipher suite, KEM, KDF, or AEAD is requested."""


class CredentialRevocationError(RFC9420Error):
    """Raised when a credential is determined to be revoked (CRL/OCSP)."""


class ConfigurationError(RFC9420Error):
    """Raised when required configuration or keys are missing."""


class CredentialValidationError(RFC9420Error):
    """Raised for credential/chain validation failures unrelated to revocation."""


class CannotDecryptOwnMessageError(CryptoError):
    """Raised when a member attempts to decrypt their own application message (OpenMLS parity)."""


class PendingCommitError(StateError):
    """Raised when an operation requires clearing/merging a pending commit first."""


class PendingProposalError(StateError):
    """Raised when operation is blocked by pending proposals."""


class NoPendingCommitError(StateError):
    """Raised when trying to apply/merge when no pending commit exists."""


class UseAfterEvictionError(StateError):
    """Raised when operating on an inactive/evicted group instance."""


class GroupNotInitializedError(StateError):
    """Raised when operation requires initialized group state."""



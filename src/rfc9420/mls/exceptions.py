"""Custom exception hierarchy for RFC9420."""
class RFC9420Error(Exception):
    """Base class for all RFC9420 errors."""


class CommitValidationError(RFC9420Error):
    """Raised when a Commit or its referenced proposals fail validation."""


class InvalidSignatureError(RFC9420Error):
    """Raised when signature or membership tag verification fails."""


class EpochMismatchError(RFC9420Error):
    """Raised when an operation targets an unexpected or stale epoch."""


class UnsupportedCipherSuiteError(RFC9420Error):
    """Raised when an unsupported cipher suite, KEM, KDF, or AEAD is requested."""


class CredentialRevocationError(RFC9420Error):
    """Raised when a credential is determined to be revoked (CRL/OCSP)."""


class ConfigurationError(RFC9420Error):
    """Raised when required configuration or keys are missing."""


class CredentialValidationError(RFC9420Error):
    """Raised for credential/chain validation failures unrelated to revocation."""



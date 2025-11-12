class PyMLSError(Exception):
    """Base class for all PyMLS errors."""


class CommitValidationError(PyMLSError):
    """Raised when a Commit or its referenced proposals fail validation."""


class InvalidSignatureError(PyMLSError):
    """Raised when signature or membership tag verification fails."""


class EpochMismatchError(PyMLSError):
    """Raised when an operation targets an unexpected or stale epoch."""


class UnsupportedCipherSuiteError(PyMLSError):
    """Raised when an unsupported cipher suite, KEM, KDF, or AEAD is requested."""


class CredentialRevocationError(PyMLSError):
    """Raised when a credential is determined to be revoked (CRL/OCSP)."""


class ConfigurationError(PyMLSError):
    """Raised when required configuration or keys are missing."""


class CredentialValidationError(PyMLSError):
    """Raised for credential/chain validation failures unrelated to revocation."""



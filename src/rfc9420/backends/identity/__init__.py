"""Identity backend implementations (batteries included)."""
from .x509_validator import X509IdentityProvider

__all__ = ["X509IdentityProvider"]

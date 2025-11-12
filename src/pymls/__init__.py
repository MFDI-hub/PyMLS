import warnings

from .mls.group import Group  # High-level API
from .crypto.default_crypto_provider import DefaultCryptoProvider

# Deprecated adapter
warnings.warn(
    "MLSGroup is deprecated; use pymls.Group instead. MLSGroup will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)
from .protocol.mls_group import MLSGroup

__all__ = ["Group", "DefaultCryptoProvider", "MLSGroup"]


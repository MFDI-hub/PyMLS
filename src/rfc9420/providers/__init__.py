"""Provider interfaces and configuration for pluggable MLS backends.

This package defines abstract protocols for crypto, storage, and identity,
plus the GroupConfig composition object used when creating or loading groups.
"""
from .crypto import CryptoProviderProtocol
from .rand import RandProviderProtocol
from .storage import StorageProviderProtocol, GroupEpochState
from .identity import IdentityProviderProtocol
from .config import GroupConfig

__all__ = [
    "CryptoProviderProtocol",
    "RandProviderProtocol",
    "StorageProviderProtocol",
    "GroupEpochState",
    "IdentityProviderProtocol",
    "GroupConfig",
]

"""PyMLS: A minimal, pragmatic MLS (Messaging Layer Security) implementation for Python.

This package provides a pure Python implementation of RFC 9420 (Messaging Layer Security).
It includes core protocol types, cryptographic operations, and a high-level Group API
for managing MLS groups.

Main exports:
    - Group: High-level API for MLS group operations
    - DefaultCryptoProvider: Concrete crypto provider using cryptography library
    - MLSGroup: Low-level protocol implementation

Example:
    >>> from pymls import Group, DefaultCryptoProvider
    >>> crypto = DefaultCryptoProvider()
    >>> group = Group.create(b"group1", key_package, crypto)
"""

from .mls.group import Group  # High-level API
from .crypto.default_crypto_provider import DefaultCryptoProvider
from .protocol.mls_group import MLSGroup  # Low-level protocol implementation
from .protocol.data_structures import CipherSuite
from .api import MLSGroupSession

__all__ = ["Group", "DefaultCryptoProvider", "MLSGroup", "MLSGroupSession", "CipherSuite"]

__version__ = "0.2.0"

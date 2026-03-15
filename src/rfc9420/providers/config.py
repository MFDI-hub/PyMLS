"""Group configuration composing crypto, storage, and identity providers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .crypto import CryptoProviderProtocol
from .rand import RandProviderProtocol
from .storage import StorageProviderProtocol
from .identity import IdentityProviderProtocol


@dataclass(frozen=True)
class GroupConfig:
    """Configuration for MLS group operations: providers and optional settings.

    Wire up your chosen "batteries" (or custom implementations) when
    creating or loading a group.

    Parameters
    ----------
    crypto_provider : CryptoProviderProtocol
        Provider for HPKE, AEAD, KDF, hashing, signing.
    storage_provider : StorageProviderProtocol
        Provider for key packages, proposals, and group state persistence.
    identity_provider : Optional[IdentityProviderProtocol], optional
        Provider for credential validation (default None).
    rand_provider : Optional[RandProviderProtocol], optional
        Provider for secure random bytes. If None, a default OS-backed
        provider is used.
    tree_backend_id : str, optional
        Ratchet tree backend id (default "array").
    secret_tree_window_size : int, optional
        Secret tree window size (default 128).
    max_generation_gap : int, optional
        Max generation gap (default 1000).
    aead_limit_bytes : Optional[int], optional
        AEAD limit in bytes (default None).
    """

    crypto_provider: CryptoProviderProtocol
    storage_provider: StorageProviderProtocol
    identity_provider: Optional[IdentityProviderProtocol] = None
    rand_provider: Optional[RandProviderProtocol] = None
    tree_backend_id: str = "array"
    secret_tree_window_size: int = 128
    max_generation_gap: int = 1000
    aead_limit_bytes: Optional[int] = None

    def resolved_rand_provider(self) -> RandProviderProtocol:
        """Return configured randomness provider or default implementation."""
        if self.rand_provider is not None:
            return self.rand_provider
        from ..backends.crypto.default_rand import DefaultRandProvider

        return DefaultRandProvider()

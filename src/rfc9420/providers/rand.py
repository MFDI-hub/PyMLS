"""Protocol for randomness operations required by MLS."""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class RandProviderProtocol(Protocol):
    """Interface for secure random byte generation."""

    def random_bytes(self, length: int) -> bytes:
        """Return `length` bytes of cryptographically secure randomness."""
        ...

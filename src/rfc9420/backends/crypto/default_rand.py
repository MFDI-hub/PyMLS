"""Default randomness backend."""
from __future__ import annotations

import secrets


class DefaultRandProvider:
    """Cryptographically secure random bytes using the OS CSPRNG."""

    def random_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("length must be non-negative")
        return secrets.token_bytes(length)

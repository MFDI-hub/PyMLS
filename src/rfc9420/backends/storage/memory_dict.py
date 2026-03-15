"""In-memory dict-based storage backend (alias).

Re-exports MemoryStorageProvider from memory.py for compatibility.
Prefer: from rfc9420.backends.storage import MemoryStorageProvider
"""
from __future__ import annotations

from .memory import MemoryStorageProvider

__all__ = ["MemoryStorageProvider"]

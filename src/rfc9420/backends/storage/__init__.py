"""Storage backend implementations."""
from .memory import MemoryStorageProvider

__all__ = ["MemoryStorageProvider", "SQLiteStorageProvider"]


def __getattr__(name: str):
    if name == "SQLiteStorageProvider":
        from .sqlite import SQLiteStorageProvider
        return SQLiteStorageProvider
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

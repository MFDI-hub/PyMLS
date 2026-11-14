"""Utility helpers for cryptographic memory handling.

This module provides utilities for secure memory operations used throughout
the cryptographic operations in RFC9420.
"""
from __future__ import annotations


def secure_wipe(buf: bytearray) -> None:
    """Overwrite this bytearray with zeros in place.

    Only the object passed in is modified. ``secure_wipe(bytearray(some_bytes))``
    clears a temporary copy and leaves ``some_bytes`` unchanged, because
    ``bytes`` objects cannot be overwritten. Callers that need a secret to
    become unreadable should drop the reference (assign ``b""``) as well.
    CPython may still retain the previous allocation until garbage collection.

    Args:
        buf: The bytearray to wipe. Modified in-place.
    """
    for i in range(len(buf)):
        buf[i] = 0



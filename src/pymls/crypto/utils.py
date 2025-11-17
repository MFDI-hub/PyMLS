"""Utility helpers for cryptographic memory handling.

This module provides utilities for secure memory operations used throughout
the cryptographic operations in PyMLS.
"""
from __future__ import annotations


def secure_wipe(buf: bytearray) -> None:
    """
    Overwrite the provided bytearray with zeros in-place.

    This function attempts to clear sensitive data from memory. Note that
    in Python, memory management is handled by the interpreter, so this
    provides best-effort clearing but cannot guarantee complete erasure.

    Args:
        buf: The bytearray to wipe. Modified in-place.

    Example:
        >>> key = bytearray(b"secret_key_data")
        >>> secure_wipe(key)
        >>> # key now contains zeros
    """
    for i in range(len(buf)):
        buf[i] = 0



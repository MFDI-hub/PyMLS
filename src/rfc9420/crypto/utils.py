"""Utility helpers for cryptographic memory handling.

This module provides utilities for secure memory operations used throughout
the cryptographic operations in RFC9420.
"""
from __future__ import annotations


def secure_wipe(buf: bytearray) -> None:
    """Overwrite a bytearray this process owns.

    ``bytes`` cannot be overwritten. ``secure_wipe(bytearray(some_bytes))``
    zeros a throwaway copy and leaves ``some_bytes`` in memory, so that call
    does not provide forward secrecy. Pass the ``bytearray`` that stores the
    secret (ratchet state does this). CPython can still keep an old
    allocation until that object is collected.

    Args:
        buf: The bytearray to wipe. Modified in-place.
    """
    for i in range(len(buf)):
        buf[i] = 0



"""Compatibility shim for legacy CryptoProvider imports.

The protocol-level code now relies on provider protocols in ``rfc9420.providers``.
This module keeps legacy import paths working while the refactor is in progress.
"""
from __future__ import annotations

from ..providers.crypto import CryptoProviderProtocol

# Backward-compatible name used across protocol modules.
CryptoProvider = CryptoProviderProtocol


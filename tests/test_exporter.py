"""RFC 9420 §8.5 MLS-Exporter hashes Context before ExpandWithLabel."""

from __future__ import annotations

import hashlib

from rfc9420.extensions.extensions import ExtensionType, leaf_supports_group_extension
from rfc9420.protocol.schedule.key_schedule import KeySchedule


class _CaptureCrypto:
    """Minimal CryptoProvider stand-in that records ExpandWithLabel context."""

    def __init__(self) -> None:
        self.expand_contexts: list[bytes] = []

    def hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def derive_secret(self, secret: bytes, label: bytes) -> bytes:
        return b"\x11" * 32

    def expand_with_label(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        self.expand_contexts.append(context)
        return b"\x22" * length


def test_export_hashes_context() -> None:
    crypto = _CaptureCrypto()
    ks = KeySchedule.__new__(KeySchedule)
    ks._crypto_provider = crypto
    ks._exporter_secret = b"\x33" * 32
    context = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    result = ks.export(b"Discord Secure Frames v0", context, 16)
    assert result == b"\x22" * 16
    assert crypto.expand_contexts == [hashlib.sha256(context).digest()]


def test_leaf_supports_default_group_extensions_when_unadvertised() -> None:
    """RFC 9420 §7.2: default types including external_senders need not be listed."""
    assert leaf_supports_group_extension(set(), ExtensionType.EXTERNAL_SENDERS)
    assert leaf_supports_group_extension(set(), ExtensionType.RATCHET_TREE)
    assert not leaf_supports_group_extension(set(), 0xF000)

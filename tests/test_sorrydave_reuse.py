from __future__ import annotations

import hashlib
import hmac
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("sorrydave")
from sorrydave.errors import DaveError
from sorrydave.crypto.sender_ratchet import SenderRatchet
from sorrydave.mls_bridge.bridge import EXPORT_LABEL, MlsBridge


def _expected_generation_key(base: bytes, generation: int) -> bytes:
    digest = hmac.new(base, b"generation:" + generation.to_bytes(8, "big"), hashlib.sha256).digest()
    return digest[:16]


def test_sender_ratchet_derived_key_unchanged():
    base_secret = b"base_secret_16_b!"
    ratchet = SenderRatchet(base_secret=base_secret)
    assert ratchet.get(3) == _expected_generation_key(base_secret, 3)
    assert ratchet.get(3) == _expected_generation_key(base_secret, 3)


def test_sender_ratchet_close_wipes_buffers():
    ratchet = SenderRatchet(base_secret=b"base_secret_16_b!")
    _ = ratchet.get(1)
    assert ratchet._cache  # internal assertion for wipe behavior
    ratchet.close()
    assert all(b == 0 for b in ratchet._base)
    assert ratchet._cache == {}


class _FakeInner:
    def get_epoch_authenticator(self) -> bytes:
        return b"epoch_auth"


class _FakeGroup:
    def __init__(self):
        self._inner = _FakeInner()


class _FakeSession:
    def __init__(self):
        self.epoch = 7
        self._group = _FakeGroup()
        self.calls: list[tuple[bytes, bytes, int]] = []

    def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
        self.calls.append((label, context, length))
        return b"k" * length


def test_mls_bridge_uses_session_protocol_methods():
    session = _FakeSession()
    bridge = MlsBridge(session=session)
    secret = bridge.export_sender_base_secret(99)
    assert secret == b"k" * 16
    assert bridge.epoch == 7
    assert bridge.get_epoch_authenticator() == b"epoch_auth"
    assert session.calls == [(EXPORT_LABEL, (99).to_bytes(8, "little"), 16)]


def test_mls_bridge_missing_group_raises_dave_error():
    class _NoGroupSession:
        epoch = 0

        def export_secret(self, label: bytes, context: bytes, length: int) -> bytes:
            return b"x" * length

    bridge = MlsBridge(session=_NoGroupSession())
    with pytest.raises(DaveError):
        bridge.get_epoch_authenticator()

"""Deterministic-like test vector generation helpers for protocol components."""
from __future__ import annotations

from typing import Dict, Any

from .key_schedule import KeySchedule
from .data_structures import GroupContext
from ..crypto.default_crypto_provider import DefaultCryptoProvider


def generate_key_schedule_vector() -> Dict[str, Any]:
    """Produce a dictionary with hex-encoded key schedule secrets for testing."""
    crypto = DefaultCryptoProvider()
    gc = GroupContext(b"group", 1, b"tree", b"cth")
    ks = KeySchedule(b"init", b"commit", gc, None, crypto)
    return {
        "epoch_secret": ks.epoch_secret.hex(),
        "handshake_secret": ks.handshake_secret.hex(),
        "application_secret": ks.application_secret.hex(),
        "exporter_secret": ks.exporter_secret.hex(),
        "confirmation_key": ks.confirmation_key.hex(),
        "membership_key": ks.membership_key.hex(),
        "resumption_psk": ks.resumption_psk.hex(),
    }



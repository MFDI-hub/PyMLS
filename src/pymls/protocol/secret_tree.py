from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from ..crypto.crypto_provider import CryptoProvider


def _u64(x: int) -> bytes:
    return x.to_bytes(8, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class _LeafState:
    app_generation: int = 0
    hs_generation: int = 0


class SecretTree:
    """
    Simplified secret tree interface. This is not the full TreeKEM secret tree,
    but provides per-sender, per-generation key/nonce derivation for
    application and handshake traffic.
    """

    def __init__(self, application_secret: bytes, handshake_secret: bytes, crypto: CryptoProvider):
        self._app_secret = application_secret
        self._hs_secret = handshake_secret
        self._crypto = crypto
        self._leaves: Dict[int, _LeafState] = {}

    def _get_leaf_state(self, leaf: int) -> _LeafState:
        if leaf not in self._leaves:
            self._leaves[leaf] = _LeafState()
        return self._leaves[leaf]

    def _derive_leaf_secret(self, base: bytes, leaf: int) -> bytes:
        label = b"leaf|" + _u64(leaf)
        return self._crypto.kdf_expand(base, label, self._crypto.kdf_hash_len())

    def _derive_generation_secret(self, leaf_secret: bytes, generation: int) -> bytes:
        label = b"gen|" + _u64(generation)
        return self._crypto.kdf_expand(leaf_secret, label, self._crypto.kdf_hash_len())

    def _derive_key_nonce(self, gen_secret: bytes) -> Tuple[bytes, bytes]:
        key = self._crypto.kdf_expand(gen_secret, b"key", self._crypto.aead_key_size())
        nonce_base = self._crypto.kdf_expand(gen_secret, b"nonce", self._crypto.aead_nonce_size())
        return key, nonce_base

    def _nonce_for_generation(self, nonce_base: bytes, generation: int) -> bytes:
        # XOR with generation encoded as big-endian and left-padded with zeros
        g_bytes = generation.to_bytes(len(nonce_base), "big", signed=False)
        return _xor(nonce_base, g_bytes)

    # Application traffic
    def next_application(self, leaf: int) -> Tuple[bytes, bytes, int]:
        st = self._get_leaf_state(leaf)
        gen = st.app_generation
        st.app_generation += 1
        return self.application_for(leaf, gen)

    def application_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        leaf_secret = self._derive_leaf_secret(self._app_secret, leaf)
        gen_secret = self._derive_generation_secret(leaf_secret, generation)
        key, nonce_base = self._derive_key_nonce(gen_secret)
        nonce = self._nonce_for_generation(nonce_base, generation)
        return key, nonce, generation

    # Handshake traffic
    def next_handshake(self, leaf: int) -> Tuple[bytes, bytes, int]:
        st = self._get_leaf_state(leaf)
        gen = st.hs_generation
        st.hs_generation += 1
        return self.handshake_for(leaf, gen)

    def handshake_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        leaf_secret = self._derive_leaf_secret(self._hs_secret, leaf)
        gen_secret = self._derive_generation_secret(leaf_secret, generation)
        key, nonce_base = self._derive_key_nonce(gen_secret)
        nonce = self._nonce_for_generation(nonce_base, generation)
        return key, nonce, generation



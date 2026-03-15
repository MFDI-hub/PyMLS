"""Secret tree for deriving per-sender keys and nonces (RFC 9420 §9).

Maintains a single tree rooted at the epoch's encryption_secret. For each leaf,
the leaf node secret is derived by walking the array-based tree (Appendix C),
then split into handshake/application branch ratchet secrets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, Union
from collections import OrderedDict

from ...crypto.crypto_provider import CryptoProvider
from ...crypto.utils import secure_wipe
from . import tree_math


@dataclass
class _LeafState:
    """Mutable per-leaf state for tracking send generations and ratchet secrets."""
    app_generation: int = 0
    hs_generation: int = 0
    app_secret: Optional[bytearray] = None
    hs_secret: Optional[bytearray] = None
    app_recv_generation: int = 0
    app_recv_secret: Optional[bytearray] = None
    app_skipped: "OrderedDict[int, Tuple[bytearray, bytearray]]" = field(default_factory=OrderedDict)
    hs_recv_generation: int = 0
    hs_recv_secret: Optional[bytearray] = None
    hs_skipped: "OrderedDict[int, Tuple[bytearray, bytearray]]" = field(default_factory=OrderedDict)


class SecretTree:
    """RFC 9420 §9 Secret Tree: single tree per epoch rooted at encryption_secret."""

    def __init__(
        self,
        encryption_secret: bytes,
        crypto: CryptoProvider,
        n_leaves: int = 1,
        window_size: int = 128,
        max_generation_gap: int = 1000,
        aead_limit_bytes: Optional[int] = None,
    ):
        self._root_secret = bytearray(encryption_secret)
        self._crypto = crypto
        self._n_leaves = max(1, int(n_leaves))
        self._window_size = max(0, int(window_size))
        self._max_generation_gap = max(1, int(max_generation_gap))
        self._aead_limit_bytes = aead_limit_bytes if aead_limit_bytes is None else max(0, int(aead_limit_bytes))
        self._encrypted_bytes_total = 0
        self._leaves: Dict[int, _LeafState] = {}

    def _get_leaf_state(self, leaf: int) -> _LeafState:
        if leaf not in self._leaves:
            self._leaves[leaf] = _LeafState()
        return self._leaves[leaf]

    def _derive_leaf_secret(self, root_secret: Union[bytes, bytearray], leaf: int) -> bytes:
        n = self._n_leaves
        if leaf < 0 or leaf >= n:
            raise ValueError("leaf index out of range for current tree")
        node = tree_math.root(n)
        target = leaf * 2
        secret = bytes(root_secret)
        hash_len = self._crypto.kdf_hash_len()
        while node != target:
            left_secret = self._crypto.expand_with_label(secret, b"tree", b"left", hash_len)
            right_secret = self._crypto.expand_with_label(secret, b"tree", b"right", hash_len)
            left_node = tree_math.left(node)
            right_node = tree_math.right(node, n)
            if target < node:
                try:
                    secure_wipe(bytearray(right_secret))
                except Exception:
                    pass
                secret = left_secret
                node = left_node
            else:
                try:
                    secure_wipe(bytearray(left_secret))
                except Exception:
                    pass
                secret = right_secret
                node = right_node
        return secret

    def _ratchet_step(self, current_secret: bytes, generation: int) -> tuple[bytes, bytes, bytes]:
        ctx = generation.to_bytes(4, "big")
        key = self._crypto.expand_with_label(current_secret, b"key", ctx, self._crypto.aead_key_size())
        nonce = self._crypto.expand_with_label(current_secret, b"nonce", ctx, self._crypto.aead_nonce_size())
        next_secret = self._crypto.expand_with_label(current_secret, b"secret", ctx, self._crypto.kdf_hash_len())
        return key, nonce, next_secret

    def next_application(self, leaf: int) -> Tuple[bytes, bytes, int]:
        st = self._get_leaf_state(leaf)
        if st.app_secret is None:
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            st.app_secret = bytearray(self._crypto.derive_secret(leaf_secret, b"application"))
            try:
                secure_wipe(bytearray(leaf_secret))
            except Exception:
                pass
            st.app_generation = 0
        gen = st.app_generation
        key, nonce, next_secret = self._ratchet_step(bytes(st.app_secret), gen)
        try:
            secure_wipe(st.app_secret)
        except Exception:
            pass
        st.app_secret = bytearray(next_secret)
        st.app_generation += 1
        key_out, nonce_out = bytes(key), bytes(nonce)
        try:
            secure_wipe(bytearray(key))
            secure_wipe(bytearray(nonce))
        except Exception:
            pass
        return key_out, nonce_out, gen

    def application_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        if generation < 0:
            raise ValueError("generation must be non-negative")
        st = self._get_leaf_state(leaf)
        if st.app_recv_secret is None:
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            st.app_recv_secret = bytearray(self._crypto.derive_secret(leaf_secret, b"application"))
            try:
                secure_wipe(bytearray(leaf_secret))
            except Exception:
                pass
            st.app_recv_generation = 0
        if generation - st.app_recv_generation > self._max_generation_gap:
            raise ValueError("application generation exceeds max_generation_gap")
        if generation < st.app_recv_generation:
            if generation in st.app_skipped:
                key, nonce = st.app_skipped.pop(generation)
                key_out, nonce_out = bytes(key), bytes(nonce)
                try:
                    secure_wipe(key)
                    secure_wipe(nonce)
                except Exception:
                    pass
                return key_out, nonce_out, generation
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            secret = self._crypto.derive_secret(leaf_secret, b"application")
            try:
                secure_wipe(bytearray(leaf_secret))
            except Exception:
                pass
            key, nonce = bytearray(), bytearray()
            for g in range(generation + 1):
                k, n, secret = self._ratchet_step(secret, g)
                key, nonce = bytearray(k), bytearray(n)
            key_out, nonce_out = bytes(key), bytes(nonce)
            try:
                secure_wipe(key)
                secure_wipe(nonce)
                secure_wipe(bytearray(secret))
            except Exception:
                pass
            return key_out, nonce_out, generation
        if self._window_size > 0 and generation > st.app_recv_generation:
            temp_secret = st.app_recv_secret
            assert temp_secret is not None
            for g in range(st.app_recv_generation, generation):
                k, n, next_temp = self._ratchet_step(bytes(temp_secret), g)
                st.app_skipped[g] = (bytearray(k), bytearray(n))
                temp_secret = bytearray(next_temp)
                while len(st.app_skipped) > self._window_size:
                    _evicted_g, (evicted_k, evicted_n) = st.app_skipped.popitem(last=False)
                    try:
                        secure_wipe(evicted_k)
                        secure_wipe(evicted_n)
                    except Exception:
                        pass
            st.app_recv_secret = temp_secret
            st.app_recv_generation = generation
        assert st.app_recv_secret is not None
        old_secret = st.app_recv_secret
        k, n, next_secret = self._ratchet_step(bytes(old_secret), generation)
        try:
            secure_wipe(old_secret)
        except Exception:
            pass
        st.app_recv_secret = bytearray(next_secret)
        st.app_recv_generation = generation + 1
        key_out, nonce_out = bytes(k), bytes(n)
        try:
            secure_wipe(bytearray(k))
            secure_wipe(bytearray(n))
        except Exception:
            pass
        return key_out, nonce_out, generation

    def next_handshake(self, leaf: int) -> Tuple[bytes, bytes, int]:
        st = self._get_leaf_state(leaf)
        if st.hs_secret is None:
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            st.hs_secret = bytearray(self._crypto.derive_secret(leaf_secret, b"handshake"))
            try:
                secure_wipe(bytearray(leaf_secret))
            except Exception:
                pass
            st.hs_generation = 0
        gen = st.hs_generation
        k, n, next_secret = self._ratchet_step(bytes(st.hs_secret), gen)
        try:
            secure_wipe(st.hs_secret)
        except Exception:
            pass
        st.hs_secret = bytearray(next_secret)
        st.hs_generation += 1
        key_out, nonce_out = bytes(k), bytes(n)
        try:
            secure_wipe(bytearray(k))
            secure_wipe(bytearray(n))
        except Exception:
            pass
        return key_out, nonce_out, gen

    def handshake_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        if generation < 0:
            raise ValueError("generation must be non-negative")
        st = self._get_leaf_state(leaf)
        if st.hs_recv_secret is None:
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            st.hs_recv_secret = bytearray(self._crypto.derive_secret(leaf_secret, b"handshake"))
            try:
                secure_wipe(bytearray(leaf_secret))
            except Exception:
                pass
            st.hs_recv_generation = 0
        if generation - st.hs_recv_generation > self._max_generation_gap:
            raise ValueError("handshake generation exceeds max_generation_gap")
        if generation < st.hs_recv_generation:
            if generation in st.hs_skipped:
                key, nonce = st.hs_skipped.pop(generation)
                key_out, nonce_out = bytes(key), bytes(nonce)
                try:
                    secure_wipe(key)
                    secure_wipe(nonce)
                except Exception:
                    pass
                return key_out, nonce_out, generation
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            secret = self._crypto.derive_secret(leaf_secret, b"handshake")
            try:
                secure_wipe(bytearray(leaf_secret))
            except Exception:
                pass
            key, nonce = bytearray(), bytearray()
            for g in range(generation + 1):
                k, n, secret = self._ratchet_step(secret, g)
                key, nonce = bytearray(k), bytearray(n)
            key_out, nonce_out = bytes(key), bytes(nonce)
            try:
                secure_wipe(key)
                secure_wipe(nonce)
                secure_wipe(bytearray(secret))
            except Exception:
                pass
            return key_out, nonce_out, generation
        if self._window_size > 0 and generation > st.hs_recv_generation:
            temp_secret = st.hs_recv_secret
            assert temp_secret is not None
            for g in range(st.hs_recv_generation, generation):
                k, n, next_temp = self._ratchet_step(bytes(temp_secret), g)
                st.hs_skipped[g] = (bytearray(k), bytearray(n))
                temp_secret = bytearray(next_temp)
                while len(st.hs_skipped) > self._window_size:
                    _evicted_g, (evicted_k, evicted_n) = st.hs_skipped.popitem(last=False)
                    try:
                        secure_wipe(evicted_k)
                        secure_wipe(evicted_n)
                    except Exception:
                        pass
            st.hs_recv_secret = temp_secret
            st.hs_recv_generation = generation
        assert st.hs_recv_secret is not None
        old_secret = st.hs_recv_secret
        k, n, next_secret = self._ratchet_step(bytes(old_secret), generation)
        try:
            secure_wipe(old_secret)
        except Exception:
            pass
        st.hs_recv_secret = bytearray(next_secret)
        st.hs_recv_generation = generation + 1
        key_out, nonce_out = bytes(k), bytes(n)
        try:
            secure_wipe(bytearray(k))
            secure_wipe(bytearray(n))
        except Exception:
            pass
        return key_out, nonce_out, generation

    def can_encrypt(self, plaintext_len: int) -> bool:
        if self._aead_limit_bytes is None:
            return True
        return (self._encrypted_bytes_total + max(0, int(plaintext_len))) <= self._aead_limit_bytes

    def record_encryption(self, plaintext_len: int) -> None:
        self._encrypted_bytes_total += max(0, int(plaintext_len))

    @property
    def encrypted_bytes_this_epoch(self) -> int:
        return int(self._encrypted_bytes_total)

    def wipe(self) -> None:
        try:
            from ...crypto.utils import secure_wipe
            val = getattr(self, "_root_secret", None)
            if isinstance(val, bytearray) and val:
                secure_wipe(val)
            elif isinstance(val, bytes) and val:
                secure_wipe(bytearray(val))
            for st in self._leaves.values():
                for name in ("app_secret", "hs_secret", "app_recv_secret", "hs_recv_secret"):
                    sval = getattr(st, name, None)
                    if isinstance(sval, bytearray) and sval:
                        try:
                            secure_wipe(sval)
                        except Exception:
                            pass
                    elif isinstance(sval, bytes) and sval:
                        try:
                            secure_wipe(bytearray(sval))
                        except Exception:
                            pass
                try:
                    for _g, (k, n) in list(st.app_skipped.items()):
                        if isinstance(k, bytearray):
                            secure_wipe(k)
                        if isinstance(n, bytearray):
                            secure_wipe(n)
                    for _g, (k, n) in list(st.hs_skipped.items()):
                        if isinstance(k, bytearray):
                            secure_wipe(k)
                        if isinstance(n, bytearray):
                            secure_wipe(n)
                except Exception:
                    pass
        except Exception:
            pass
        self._leaves.clear()

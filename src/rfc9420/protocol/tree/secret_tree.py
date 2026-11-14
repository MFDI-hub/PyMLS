"""Secret tree for deriving per-sender keys and nonces (RFC 9420 §9).

Maintains a single tree rooted at the epoch's encryption_secret. For each leaf,
the leaf node secret is derived by walking the array-based tree (Appendix C),
then split into handshake/application branch ratchet secrets.
"""
from __future__ import annotations

import copy
import struct
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass, field

from ...crypto.crypto_provider import CryptoProvider
from ...crypto.utils import secure_wipe
from . import tree_math


@dataclass
class _LeafState:
    """Mutable per-leaf state for tracking send generations and ratchet secrets."""
    app_generation: int = 0
    hs_generation: int = 0
    app_secret: bytearray | None = None
    hs_secret: bytearray | None = None
    app_recv_generation: int = 0
    app_recv_secret: bytearray | None = None
    app_skipped: "OrderedDict[int, tuple[bytearray, bytearray]]" = field(default_factory=OrderedDict)
    hs_recv_generation: int = 0
    hs_recv_secret: bytearray | None = None
    hs_skipped: "OrderedDict[int, tuple[bytearray, bytearray]]" = field(default_factory=OrderedDict)


def _pack_secret(buf: bytearray | None) -> bytes:
    raw = b"" if buf is None else bytes(buf)
    if len(raw) > 0xFFFF:
        raise ValueError("secret too long to persist")
    return struct.pack("!H", len(raw)) + raw


def _pack_skipped(skipped: OrderedDict[int, tuple[bytearray, bytearray]]) -> bytes:
    items = list(skipped.items())
    if len(items) > 0xFFFF:
        raise ValueError("skipped-key window too large to persist")
    parts = [struct.pack("!H", len(items))]
    for gen, (key, nonce) in items:
        key_b, nonce_b = bytes(key), bytes(nonce)
        if len(key_b) > 0xFFFF or len(nonce_b) > 0xFFFF:
            raise ValueError("skipped key too long to persist")
        parts.append(struct.pack("!I", gen))
        parts.append(struct.pack("!H", len(key_b)) + key_b)
        parts.append(struct.pack("!H", len(nonce_b)) + nonce_b)
    return b"".join(parts)


def _read_uint(buf: bytes, offset: int, nbytes: int) -> tuple[int, int]:
    end = offset + nbytes
    if end > len(buf):
        raise ValueError("secret-tree replay state is truncated")
    return int.from_bytes(buf[offset:end], "big"), end


def _unpack_secret(buf: bytes, offset: int) -> tuple[bytearray | None, int]:
    length, offset = _read_uint(buf, offset, 2)
    end = offset + length
    if end > len(buf):
        raise ValueError("secret-tree replay state is truncated")
    raw = buf[offset:end]
    return (bytearray(raw) if raw else None), end


def _unpack_skipped(
    buf: bytes, offset: int
) -> tuple[OrderedDict[int, tuple[bytearray, bytearray]], int]:
    count, offset = _read_uint(buf, offset, 2)
    skipped: OrderedDict[int, tuple[bytearray, bytearray]] = OrderedDict()
    for _ in range(count):
        gen, offset = _read_uint(buf, offset, 4)
        key, offset = _unpack_secret(buf, offset)
        nonce, offset = _unpack_secret(buf, offset)
        if key is None or nonce is None or gen in skipped:
            raise ValueError("secret-tree replay state has an invalid skipped key")
        skipped[gen] = (key, nonce)
    return skipped, offset


class SecretTree:
    """RFC 9420 §9 Secret Tree: single tree per epoch rooted at encryption_secret."""

    def __init__(
        self,
        encryption_secret: bytes,
        crypto: CryptoProvider,
        n_leaves: int = 1,
        window_size: int = 128,
        max_generation_gap: int = 1000,
        aead_limit_bytes: int | None = None,
    ):
        self._root_secret = bytearray(encryption_secret)
        self._crypto = crypto
        self._n_leaves = max(1, int(n_leaves))
        self._window_size = max(0, int(window_size))
        self._max_generation_gap = max(1, int(max_generation_gap))
        self._aead_limit_bytes = aead_limit_bytes if aead_limit_bytes is None else max(0, int(aead_limit_bytes))
        self._encrypted_bytes_total = 0
        self._leaves: dict[int, _LeafState] = {}

    def checkpoint_leaf(self, leaf: int) -> _LeafState | None:
        """Deep-copy one leaf's ratchet state, or None if that leaf is untouched."""
        state = self._leaves.get(leaf)
        if state is None:
            return None
        return copy.deepcopy(state)

    def restore_leaf(self, leaf: int, checkpoint: _LeafState | None) -> None:
        """Put back a checkpoint from ``checkpoint_leaf``. None drops the leaf."""
        if checkpoint is None:
            self._leaves.pop(leaf, None)
        else:
            self._leaves[leaf] = checkpoint

    @contextmanager
    def tentative_receive(self, leaf: int):
        """Roll back this leaf's receive ratchet if the body raises.

        ``application_for`` / ``handshake_for`` advance state as they derive
        keys. Decryption must run inside this context so a failed AEAD open
        does not consume a generation or evict skipped keys.
        """
        checkpoint = self.checkpoint_leaf(leaf)
        try:
            yield
        except Exception:
            self.restore_leaf(leaf, checkpoint)
            raise

    def _get_leaf_state(self, leaf: int) -> _LeafState:
        if leaf not in self._leaves:
            self._leaves[leaf] = _LeafState()
        return self._leaves[leaf]

    def _derive_leaf_secret(self, root_secret: bytes | bytearray, leaf: int) -> bytes:
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

    def next_application(self, leaf: int) -> tuple[bytes, bytes, int]:
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

    def application_for(self, leaf: int, generation: int) -> tuple[bytes, bytes, int]:
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
            # RFC 9420 §9.2: a consumed generation is deleted. Re-deriving it
            # from the epoch root would accept replays.
            raise ValueError("application generation already consumed or outside the replay window")
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

    def next_handshake(self, leaf: int) -> tuple[bytes, bytes, int]:
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

    def handshake_for(self, leaf: int, generation: int) -> tuple[bytes, bytes, int]:
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
            raise ValueError("handshake generation already consumed or outside the replay window")
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

    def export_replay_state(self) -> bytes:
        """Serialize per-leaf ratchet positions, secrets, and skipped keys.

        ``to_bytes`` stores this so a restored group does not re-derive a
        generation that was already consumed (RFC 9420 §9.2).
        """
        parts: list[bytes] = [struct.pack("!Q", self._encrypted_bytes_total & 0xFFFFFFFFFFFFFFFF)]
        leaves = sorted(self._leaves.items())
        parts.append(struct.pack("!H", len(leaves)))
        for leaf, st in leaves:
            parts.append(
                struct.pack(
                    "!IIIII",
                    leaf,
                    st.app_generation,
                    st.hs_generation,
                    st.app_recv_generation,
                    st.hs_recv_generation,
                )
            )
            parts.append(_pack_secret(st.app_secret))
            parts.append(_pack_secret(st.hs_secret))
            parts.append(_pack_secret(st.app_recv_secret))
            parts.append(_pack_secret(st.hs_recv_secret))
            parts.append(_pack_skipped(st.app_skipped))
            parts.append(_pack_skipped(st.hs_skipped))
        return b"".join(parts)

    def load_replay_state(self, data: bytes) -> None:
        """Restore state written by export_replay_state.

        Framing is checked (truncation, trailing bytes, leaf indexes,
        duplicate skipped generations). The blob is not authenticated.
        Only load bytes from storage whose integrity you already trust.
        """
        offset = 0
        total, offset = _read_uint(data, offset, 8)
        count, offset = _read_uint(data, offset, 2)
        leaves: dict[int, _LeafState] = {}
        for _ in range(count):
            leaf, offset = _read_uint(data, offset, 4)
            app_gen, offset = _read_uint(data, offset, 4)
            hs_gen, offset = _read_uint(data, offset, 4)
            app_recv, offset = _read_uint(data, offset, 4)
            hs_recv, offset = _read_uint(data, offset, 4)
            if leaf in leaves or leaf >= self._n_leaves:
                raise ValueError("secret-tree replay state has an invalid leaf index")
            app_secret, offset = _unpack_secret(data, offset)
            hs_secret, offset = _unpack_secret(data, offset)
            app_recv_secret, offset = _unpack_secret(data, offset)
            hs_recv_secret, offset = _unpack_secret(data, offset)
            app_skipped, offset = _unpack_skipped(data, offset)
            hs_skipped, offset = _unpack_skipped(data, offset)
            leaves[leaf] = _LeafState(
                app_generation=app_gen,
                hs_generation=hs_gen,
                app_secret=app_secret,
                hs_secret=hs_secret,
                app_recv_generation=app_recv,
                app_recv_secret=app_recv_secret,
                app_skipped=app_skipped,
                hs_recv_generation=hs_recv,
                hs_recv_secret=hs_recv_secret,
                hs_skipped=hs_skipped,
            )
        if offset != len(data):
            raise ValueError("secret-tree replay state has trailing bytes")
        self._encrypted_bytes_total = total
        self._leaves = leaves

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

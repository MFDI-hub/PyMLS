"""Secret tree for deriving per-sender keys and nonces (RFC 9420 §9).

Maintains a single tree rooted at the epoch's encryption_secret. For each leaf,
the leaf node secret is derived by walking the array-based tree (Appendix C),
then split into handshake/application branch ratchet secrets. Per-generation
(key, nonce) pairs are derived on demand and may be advanced monotonically for
sending via next_* helpers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from ..crypto.crypto_provider import CryptoProvider
from . import tree_math


def _u64(x: int) -> bytes:
    """Encode an integer as 8-byte big-endian."""
    return x.to_bytes(8, "big")


def _xor(a: bytes, b: bytes) -> bytes:
    """Byte-wise XOR of two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass
class _LeafState:
    """Mutable per-leaf state for tracking send generations and ratchet secrets."""
    app_generation: int = 0
    hs_generation: int = 0
    app_secret: bytes | None = None
    hs_secret: bytes | None = None


class SecretTree:
    """
    RFC 9420 §9 Secret Tree

    Single tree per epoch rooted at the epoch's encryption_secret. Leaf secrets
    are derived by walking the array-based tree (Appendix C) from the root to
    the target leaf, deriving left/right child secrets at each step. For each
    leaf, handshake/application branch ratchets are split from the leaf secret.
    Per-generation sender (key, nonce) are derived from the branch ratchet
    secret and a generation counter.

    This implementation derives receive keys on-demand (no cache).
    """

    def __init__(self, encryption_secret: bytes, crypto: CryptoProvider, n_leaves: int = 1):
        self._root_secret = encryption_secret
        self._crypto = crypto
        self._n_leaves = max(1, int(n_leaves))
        self._leaves: Dict[int, _LeafState] = {}

    def _get_leaf_state(self, leaf: int) -> _LeafState:
        if leaf not in self._leaves:
            self._leaves[leaf] = _LeafState()
        return self._leaves[leaf]

    def _derive_leaf_secret(self, root_secret: bytes, leaf: int) -> bytes:
        """
        Walk the array-based tree from root to the target leaf (RFC 9420 Appendix C),
        deriving left/right child secrets from the parent at each step using
        labeled KDF expansion per §9.2.
        """
        n = self._n_leaves
        if leaf < 0 or leaf >= n:
            raise ValueError("leaf index out of range for current tree")
        node = tree_math.root(n)
        target = leaf * 2  # leaves are at even indices
        secret = root_secret
        hash_len = self._crypto.kdf_hash_len()
        while node != target:
            # Derive children from parent
            left_secret = self._crypto.expand_with_label(secret, b"tree", b"left", hash_len)
            right_secret = self._crypto.expand_with_label(secret, b"tree", b"right", hash_len)
            # Choose next direction based on array index relation
            left_node = tree_math.left(node)
            right_node = tree_math.right(node, n)
            if target < node:
                secret = left_secret
                node = left_node
            else:
                secret = right_secret
                node = right_node
        return secret

    def _derive_generation_secret(self, branch_secret: bytes, generation: int, branch_label: bytes) -> bytes:
        """
        Derive the per-generation secret for the given branch (b"handshake" or b"application").
        """
        ctx = _u64(generation)
        # Domain-separate with the branch label before deriving (key, nonce)
        return self._crypto.expand_with_label(branch_secret, branch_label, ctx, self._crypto.kdf_hash_len())

    def _derive_key_nonce(self, gen_secret: bytes) -> Tuple[bytes, bytes]:
        """Derive (key, nonce_base) for AEAD from a generation secret."""
        key = self._crypto.expand_with_label(gen_secret, b"key", b"", self._crypto.aead_key_size())
        nonce_base = self._crypto.expand_with_label(gen_secret, b"nonce", b"", self._crypto.aead_nonce_size())
        return key, nonce_base

    def _nonce_for_generation(self, nonce_base: bytes, generation: int) -> bytes:
        """Derive the AEAD nonce by XORing the base with the generation counter."""
        # XOR with generation encoded as big-endian and left-padded with zeros
        g_bytes = generation.to_bytes(len(nonce_base), "big", signed=False)
        return _xor(nonce_base, g_bytes)

    def _ratchet_step(self, current_secret: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Derive (key, nonce, next_secret) from the current ratchet secret per RFC §9.1:
          key   := ExpandWithLabel(secret, "key", "", Nk)
          nonce := ExpandWithLabel(secret, "nonce", "", Nn)
          next  := DeriveSecret(secret, "secret")
        """
        key = self._crypto.expand_with_label(current_secret, b"key", b"", self._crypto.aead_key_size())
        nonce = self._crypto.expand_with_label(current_secret, b"nonce", b"", self._crypto.aead_nonce_size())
        next_secret = self._crypto.derive_secret(current_secret, b"secret")
        return key, nonce, next_secret

    # Application traffic
    def next_application(self, leaf: int) -> Tuple[bytes, bytes, int]:
        """Advance application generation and return (key, nonce, generation)."""
        st = self._get_leaf_state(leaf)
        # Initialize branch ratchet secret lazily from the leaf secret
        if st.app_secret is None:
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            st.app_secret = self._crypto.derive_secret(leaf_secret, b"application")
            st.app_generation = 0
        # Derive step and advance (delete current secret)
        key, nonce, next_secret = self._ratchet_step(st.app_secret)
        try:
            ba = bytearray(st.app_secret)
            for i in range(len(ba)):
                ba[i] = 0
        except Exception:
            pass
        st.app_secret = next_secret
        gen = st.app_generation
        st.app_generation += 1
        return key, nonce, gen

    def application_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        """Return (key, nonce, generation) for a specific application generation (receive path)."""
        leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
        secret = self._crypto.derive_secret(leaf_secret, b"application")
        key = nonce = b""
        for _ in range(generation + 1):
            key, nonce, secret = self._ratchet_step(secret)
        return key, nonce, generation

    # Handshake traffic
    def next_handshake(self, leaf: int) -> Tuple[bytes, bytes, int]:
        """Advance handshake generation and return (key, nonce, generation)."""
        st = self._get_leaf_state(leaf)
        if st.hs_secret is None:
            leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
            st.hs_secret = self._crypto.derive_secret(leaf_secret, b"handshake")
            st.hs_generation = 0
        key, nonce, next_secret = self._ratchet_step(st.hs_secret)
        try:
            ba = bytearray(st.hs_secret)
            for i in range(len(ba)):
                ba[i] = 0
        except Exception:
            pass
        st.hs_secret = next_secret
        gen = st.hs_generation
        st.hs_generation += 1
        return key, nonce, gen

    def handshake_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        """Return (key, nonce, generation) for a specific handshake generation (receive path)."""
        leaf_secret = self._derive_leaf_secret(self._root_secret, leaf)
        secret = self._crypto.derive_secret(leaf_secret, b"handshake")
        key = nonce = b""
        for _ in range(generation + 1):
            key, nonce, secret = self._ratchet_step(secret)
        return key, nonce, generation


    def wipe(self) -> None:
        """
        Best-effort zeroization of sensitive secrets and state.
        """
        try:
            from ..crypto.utils import secure_wipe
            val = getattr(self, "_root_secret", None)
            if isinstance(val, (bytes, bytearray)) and val:
                ba = bytearray(val)
                secure_wipe(ba)
        except Exception:
            pass
        self._leaves.clear()


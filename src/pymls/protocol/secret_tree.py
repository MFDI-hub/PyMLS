"""Secret tree for deriving per-sender keys and nonces (RFC 9420 §9.2).

Maintains separate handshake and application trees per epoch. For each leaf,
per-generation (key, nonce) pairs are derived on demand and may be advanced
monotonically for sending via next_* helpers.
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
    """Mutable per-leaf state for tracking send generations."""
    app_generation: int = 0
    hs_generation: int = 0


class SecretTree:
    """
    RFC 9420 §9.2 Secret Tree

    Two trees per epoch (handshake/application) rooted at the epoch's
    corresponding branch secret. Leaf secrets are derived by walking
    the array-based tree (Appendix C) from the root to the target leaf,
    deriving left/right child secrets at each step. Per-generation sender
    (key, nonce) are derived from the leaf secret and a generation counter.

    This implementation derives receive keys on-demand (no cache).
    """

    def __init__(self, application_secret: bytes, handshake_secret: bytes, crypto: CryptoProvider, n_leaves: int = 1):
        self._app_secret = application_secret
        self._hs_secret = handshake_secret
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

    def _derive_generation_secret(self, leaf_secret: bytes, generation: int, branch_label: bytes) -> bytes:
        """
        Derive the per-generation secret for the given branch (b\"handshake\" or b\"application\").
        """
        ctx = _u64(generation)
        # Domain-separate with the branch label before deriving (key, nonce)
        return self._crypto.expand_with_label(leaf_secret, branch_label, ctx, self._crypto.kdf_hash_len())

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

    # Application traffic
    def next_application(self, leaf: int) -> Tuple[bytes, bytes, int]:
        """Advance application generation and return (key, nonce, generation)."""
        st = self._get_leaf_state(leaf)
        gen = st.app_generation
        st.app_generation += 1
        return self.application_for(leaf, gen)

    def application_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        """Return (key, nonce, generation) for a specific application generation."""
        leaf_secret = self._derive_leaf_secret(self._app_secret, leaf)
        gen_secret = self._derive_generation_secret(leaf_secret, generation, b"application")
        key, nonce_base = self._derive_key_nonce(gen_secret)
        nonce = self._nonce_for_generation(nonce_base, generation)
        return key, nonce, generation

    # Handshake traffic
    def next_handshake(self, leaf: int) -> Tuple[bytes, bytes, int]:
        """Advance handshake generation and return (key, nonce, generation)."""
        st = self._get_leaf_state(leaf)
        gen = st.hs_generation
        st.hs_generation += 1
        return self.handshake_for(leaf, gen)

    def handshake_for(self, leaf: int, generation: int) -> Tuple[bytes, bytes, int]:
        """Return (key, nonce, generation) for a specific handshake generation."""
        leaf_secret = self._derive_leaf_secret(self._hs_secret, leaf)
        gen_secret = self._derive_generation_secret(leaf_secret, generation, b"handshake")
        key, nonce_base = self._derive_key_nonce(gen_secret)
        nonce = self._nonce_for_generation(nonce_base, generation)
        return key, nonce, generation


    def wipe(self) -> None:
        """
        Best-effort zeroization of sensitive secrets and state.
        """
        try:
            from ..crypto.utils import secure_wipe
            for name in ["_app_secret", "_hs_secret"]:
                val = getattr(self, name, None)
                if isinstance(val, (bytes, bytearray)) and val:
                    ba = bytearray(val)
                    secure_wipe(ba)
        except Exception:
            pass
        self._leaves.clear()


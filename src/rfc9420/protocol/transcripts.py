"""Transcript hash maintenance for MLS handshake flows."""
from __future__ import annotations
from typing import Optional

from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import PyMLSError
from .messages import MLSPlaintext


class TranscriptState:
    """
    Maintains interim and confirmed transcript hashes per RFC semantics.

    This helper intentionally uses the CryptoProvider's KDF extract to
    produce fixed-length digests tied to the ciphersuite hash length,
    avoiding a direct dependency on hashing primitives in this layer.
    """

    def __init__(self, crypto: CryptoProvider, interim: Optional[bytes] = None, confirmed: Optional[bytes] = None):
        self._crypto = crypto
        self._interim = interim
        self._confirmed = confirmed

    @property
    def interim(self) -> Optional[bytes]:
        """Current interim transcript hash (or None if uninitialized)."""
        return self._interim

    @property
    def confirmed(self) -> Optional[bytes]:
        """Current confirmed transcript hash (or None if not finalized)."""
        return self._confirmed

    def update_with_handshake(self, plaintext: MLSPlaintext) -> bytes:
        """
        Update interim transcript hash per RFC §8.2:
          Interim_i = Hash(Interim_{i-1} || ConfirmedTranscriptHashInput(commit))
        For MVP, we use the handshake TBS as the input blob.
        """
        tbs = plaintext.auth_content.tbs.serialize()
        prev = self._interim or b""
        self._interim = self._crypto.hash(prev + tbs)
        return self._interim

    def compute_confirmation_tag(self, confirmation_key: bytes) -> bytes:
        """
        Compute confirmation tag as HMAC over the current interim transcript hash.
        """
        if self._interim is None:
            raise PyMLSError("interim transcript hash is not set")
        # Return full-length tag per RFC (Nh)
        return self._crypto.hmac_sign(confirmation_key, self._interim)

    def finalize_confirmed(self, confirmation_tag: bytes) -> bytes:
        """
        Update confirmed transcript hash per RFC §8.2:
          Confirmed_i = Hash(Confirmed_{i-1} || InterimTranscriptHashInput(commit, confirmation_tag))
        For MVP, we use confirmation_tag directly as the input blob.
        """
        if self._interim is None:
            raise PyMLSError("interim transcript hash is not set")
        prev_c = self._confirmed or b""
        self._confirmed = self._crypto.hash(prev_c + confirmation_tag)
        return self._confirmed

    # --- RFC 9420 §11 bootstrap helper ---
    def bootstrap_initial_interim(self) -> bytes:
        """
        Initialize the interim transcript hash at epoch 0 using an all-zero
        confirmation tag of suite hash length, hashed with previous confirmed
        (empty at creation). This mirrors the confirmed hash update shape and
        yields a non-empty interim value before the first commit.
        """
        zero_tag = bytes(self._crypto.kdf_hash_len())
        prev_c = self._confirmed or b""
        self._interim = self._crypto.hash(prev_c + zero_tag)
        return self._interim



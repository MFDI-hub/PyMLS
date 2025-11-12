from __future__ import annotations

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

    def __init__(self, crypto: CryptoProvider, interim: bytes | None = None, confirmed: bytes | None = None):
        self._crypto = crypto
        self._interim = interim
        self._confirmed = confirmed

    @property
    def interim(self) -> bytes | None:
        return self._interim

    @property
    def confirmed(self) -> bytes | None:
        return self._confirmed

    def update_with_handshake(self, plaintext: MLSPlaintext) -> bytes:
        """
        Update interim transcript hash with the serialized TBS of the handshake message.
        """
        tbs = plaintext.auth_content.tbs.serialize()
        prev = self._interim or b""
        self._interim = self._crypto.kdf_extract(prev, tbs)
        return self._interim

    def compute_confirmation_tag(self, confirmation_key: bytes) -> bytes:
        """
        Compute confirmation tag as HMAC over the current interim transcript hash.
        """
        if self._interim is None:
            raise PyMLSError("interim transcript hash is not set")
        # Truncate to 16 bytes (matches existing MVP tag length)
        return self._crypto.hmac_sign(confirmation_key, self._interim)[:16]

    def finalize_confirmed(self, confirmation_tag: bytes) -> bytes:
        """
        Update confirmed transcript hash by mixing in the confirmation_tag.
        """
        if self._interim is None:
            raise PyMLSError("interim transcript hash is not set")
        self._confirmed = self._crypto.kdf_extract(self._interim, confirmation_tag)
        return self._confirmed



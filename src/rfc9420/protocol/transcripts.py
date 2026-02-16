"""Transcript hash maintenance for MLS handshake flows (RFC 9420 §8.2)."""
from __future__ import annotations
from typing import Optional

from ..codec.tls import write_uint16, write_opaque16
from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import RFC9420Error
from .messages import MLSPlaintext, WireFormat


def serialize_confirmed_transcript_hash_input(
    wire_format: int,
    framed_content_bytes: bytes,
    signature: bytes,
) -> bytes:
    """Serialize ConfirmedTranscriptHashInput per RFC 9420 §8.2.

    struct {
        WireFormat wire_format;
        FramedContent content;
        opaque signature<V>;
    } ConfirmedTranscriptHashInput;
    """
    return (
        write_uint16(wire_format)
        + framed_content_bytes
        + write_opaque16(signature)
    )


def serialize_interim_transcript_hash_input(
    confirmation_tag: bytes,
) -> bytes:
    """Serialize InterimTranscriptHashInput per RFC 9420 §8.2.

    struct {
        MAC confirmation_tag;
    } InterimTranscriptHashInput;

    MAC is opaque<V> (length-prefixed).
    """
    return write_opaque16(confirmation_tag)


class TranscriptState:
    """
    Maintains interim and confirmed transcript hashes per RFC 9420 §8.2.

    - confirmed_transcript_hash:
        Hash(interim_i-1 || ConfirmedTranscriptHashInput_i)
      where ConfirmedTranscriptHashInput = wire_format || FramedContent || signature

    - interim_transcript_hash:
        Hash(confirmed_i || InterimTranscriptHashInput_i)
      where InterimTranscriptHashInput = confirmation_tag
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
        """Update confirmed transcript hash per RFC §8.2.

        confirmed_transcript_hash[i] =
            Hash(interim_transcript_hash[i-1] ||
                 ConfirmedTranscriptHashInput[i])

        where ConfirmedTranscriptHashInput = wire_format || FramedContent || signature
        """
        # Build ConfirmedTranscriptHashInput from the plaintext
        framed_content_bytes = plaintext.auth_content.tbs.framed_content.serialize()
        signature = plaintext.auth_content.signature
        input_bytes = serialize_confirmed_transcript_hash_input(
            WireFormat.PUBLIC_MESSAGE,
            framed_content_bytes,
            signature,
        )
        prev = self._interim or b""
        self._interim = self._crypto.hash(prev + input_bytes)
        return self._interim

    def compute_confirmation_tag(self, confirmation_key: bytes) -> bytes:
        """Compute confirmation tag as HMAC over the current interim transcript hash."""
        if self._interim is None:
            raise RFC9420Error("interim transcript hash is not set")
        return self._crypto.hmac_sign(confirmation_key, self._interim)

    def finalize_confirmed(self, confirmation_tag: bytes) -> bytes:
        """Update interim transcript hash per RFC §8.2.

        interim_transcript_hash[i] =
            Hash(confirmed_transcript_hash[i] ||
                 InterimTranscriptHashInput[i])

        where InterimTranscriptHashInput = confirmation_tag (length-prefixed)
        """
        if self._interim is None:
            raise RFC9420Error("interim transcript hash is not set")
        # The confirmed hash was set during update_with_handshake (stored as interim).
        # Per RFC: confirmed = the hash we just computed; interim = Hash(confirmed || InterimInput)
        confirmed = self._interim
        self._confirmed = confirmed

        input_bytes = serialize_interim_transcript_hash_input(confirmation_tag)
        self._interim = self._crypto.hash(confirmed + input_bytes)
        return self._confirmed

    # --- RFC 9420 §11 bootstrap helper ---
    def bootstrap_initial_interim(self) -> bytes:
        """Initialize the transcript hashes at epoch 0.

        Per RFC 9420 §8.2:
            confirmed_transcript_hash_[0] = "";  /* zero-length octet string */
            interim_transcript_hash_[0] = "";    /* zero-length octet string */

        Returns the initial (empty) interim transcript hash.
        """
        self._confirmed = b""
        self._interim = b""
        return self._interim

"""Transcript hash maintenance for MLS handshake flows (RFC 9420 §8.2)."""

from __future__ import annotations
from typing import Optional


from ..codec.tls import write_uint16, write_opaque_varint
from ..crypto.crypto_provider import CryptoProvider
from ..mls.exceptions import RFC9420Error
from ..messages.messages import MLSPlaintext


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

    Parameters
    ----------
    wire_format : int
        Wire format value (e.g. mls_plaintext).
    framed_content_bytes : bytes
        Serialized FramedContent.
    signature : bytes
        Opaque signature<V>.

    Returns
    -------
    bytes
        Serialized ConfirmedTranscriptHashInput.
    """
    return write_uint16(wire_format) + framed_content_bytes + write_opaque_varint(signature)


def serialize_interim_transcript_hash_input(
    confirmation_tag: bytes,
) -> bytes:
    """Serialize InterimTranscriptHashInput per RFC 9420 §8.2.

    struct {
        MAC confirmation_tag;
    } InterimTranscriptHashInput;

    MAC is opaque<V> (length-prefixed).

    Parameters
    ----------
    confirmation_tag : bytes
        MAC confirmation tag (opaque<V>).

    Returns
    -------
    bytes
        Serialized InterimTranscriptHashInput.
    """
    return write_opaque_varint(confirmation_tag)


class TranscriptState:
    """Maintains interim and confirmed transcript hashes per RFC 9420 §8.2.

    - confirmed_transcript_hash:
        Hash(interim_i-1 || ConfirmedTranscriptHashInput_i)
      where ConfirmedTranscriptHashInput = wire_format || FramedContent || signature

    - interim_transcript_hash:
        Hash(confirmed_i || InterimTranscriptHashInput_i)
      where InterimTranscriptHashInput = confirmation_tag

    Between update_with_handshake() and finalize_confirmed(), the newly computed
    confirmed hash is held in _pending_confirmed; _interim is only updated in
    finalize_confirmed() to the new interim hash.

    Parameters
    ----------
    crypto : CryptoProvider
        Provider for hash and HMAC operations.
    interim : Optional[bytes], optional
        Initial interim transcript hash (default None).
    confirmed : Optional[bytes], optional
        Initial confirmed transcript hash (default None).
    """

    def __init__(
        self,
        crypto: CryptoProvider,
        interim: Optional[bytes] = None,
        confirmed: Optional[bytes] = None,
    ):
        self._crypto = crypto
        self._interim = interim
        self._confirmed = confirmed
        self._pending_confirmed: Optional[bytes] = (
            None  # new confirmed hash until finalize_confirmed()
        )

    @property
    def interim(self) -> Optional[bytes]:
        """Current interim transcript hash (or None if uninitialized).

        Returns
        -------
        Optional[bytes]
            Interim transcript hash or None.
        """
        return self._interim

    @property
    def confirmed(self) -> Optional[bytes]:
        """Current confirmed transcript hash (or None if not finalized).

        Returns
        -------
        Optional[bytes]
            Confirmed transcript hash or None.
        """
        return self._confirmed

    def update_with_handshake(self, plaintext: MLSPlaintext) -> bytes:
        """Update confirmed transcript hash per RFC §8.2.

        confirmed_transcript_hash[i] =
            Hash(interim_transcript_hash[i-1] ||
                 ConfirmedTranscriptHashInput[i])

        where ConfirmedTranscriptHashInput = wire_format || FramedContent || signature

        The new confirmed hash is stored in _pending_confirmed until finalize_confirmed().

        Parameters
        ----------
        plaintext : MLSPlaintext
            Handshake plaintext to incorporate.

        Returns
        -------
        bytes
            New pending confirmed transcript hash.
        """
        # Build ConfirmedTranscriptHashInput from the plaintext (RFC 9420 §8.2: use actual wire format).
        framed_content_bytes = plaintext.auth_content.tbs.framed_content.serialize()
        signature = plaintext.auth_content.signature
        wire_format = plaintext.auth_content.tbs.wire_format
        input_bytes = serialize_confirmed_transcript_hash_input(
            wire_format,
            framed_content_bytes,
            signature,
        )
        prev = self._interim or b""
        self._pending_confirmed = self._crypto.hash(prev + input_bytes)
        return self._pending_confirmed

    def compute_confirmation_tag(self, confirmation_key: bytes) -> bytes:
        """Compute confirmation tag as HMAC over the current transcript hash used for confirmation.

        Uses the pending confirmed hash (after update_with_handshake) or the current
        interim hash (e.g. after bootstrap).

        Parameters
        ----------
        confirmation_key : bytes
            Epoch confirmation key.

        Returns
        -------
        bytes
            HMAC confirmation tag.
        """
        data = self._pending_confirmed if self._pending_confirmed is not None else self._interim
        if data is None:
            raise RFC9420Error("transcript hash is not set for confirmation tag")
        return self._crypto.hmac_sign(confirmation_key, data)

    def finalize_confirmed(self, confirmation_tag: bytes) -> bytes:
        """Update interim transcript hash per RFC §8.2.

        interim_transcript_hash[i] =
            Hash(confirmed_transcript_hash[i] ||
                 InterimTranscriptHashInput[i])

        where InterimTranscriptHashInput = confirmation_tag (length-prefixed).

        Commits the pending confirmed hash (from update_with_handshake) to _confirmed,
        then derives and stores the new interim hash.

        Parameters
        ----------
        confirmation_tag : bytes
            Confirmation tag (length-prefixed).

        Returns
        -------
        bytes
            Finalized confirmed transcript hash.
        """
        if self._pending_confirmed is None:
            raise RFC9420Error("no pending confirmed hash; call update_with_handshake first")
        confirmed = self._pending_confirmed
        self._confirmed = confirmed
        self._pending_confirmed = None

        input_bytes = serialize_interim_transcript_hash_input(confirmation_tag)
        self._interim = self._crypto.hash(confirmed + input_bytes)
        return self._confirmed

    # --- RFC 9420 §11 bootstrap helper ---
    def bootstrap_initial_interim(self, confirmation_tag: bytes) -> bytes:
        """Initialize the transcript hashes at epoch 0.

        Per RFC 9420 §11:
            The creator MUST calculate the interim transcript hash by:
            1. Deriving the confirmation_key for the epoch (Section 8).
            2. Computing a confirmation_tag over the empty confirmed_transcript_hash using the confirmation_key (Section 6.1).
            3. Computing the updated interim_transcript_hash from the confirmed_transcript_hash and the confirmation_tag (Section 8.2).

        Parameters
        ----------
        confirmation_tag : bytes
            The confirmation tag computed over the empty confirmed transcript hash.

        Returns
        -------
        bytes
            The initial interim transcript hash.
        """
        # confirmed_transcript_hash is the zero-length octet string at epoch 0
        self._confirmed = b""

        # interim_transcript_hash = Hash(confirmed || InterimTranscriptHashInput(confirmation_tag))
        input_bytes = serialize_interim_transcript_hash_input(confirmation_tag)
        self._interim = self._crypto.hash(self._confirmed + input_bytes)
        return self._interim

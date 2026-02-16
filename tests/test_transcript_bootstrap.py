from rfc9420.crypto.default_crypto_provider import DefaultCryptoProvider
from rfc9420.protocol.transcripts import TranscriptState


def test_transcript_bootstrap_initial_interim():
    crypto = DefaultCryptoProvider()
    ts = TranscriptState(crypto, interim=None, confirmed=None)
    interim = ts.bootstrap_initial_interim()
    # Per RFC 9420 §8.2: initial interim and confirmed are empty octet strings
    assert isinstance(interim, (bytes, bytearray))
    assert interim == b""

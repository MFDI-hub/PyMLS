from pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from pymls.protocol.transcripts import TranscriptState


def test_transcript_bootstrap_initial_interim():
    crypto = DefaultCryptoProvider()
    ts = TranscriptState(crypto, interim=None, confirmed=None)
    interim = ts.bootstrap_initial_interim()
    assert isinstance(interim, (bytes, bytearray))
    assert len(interim) == crypto.kdf_hash_len()
    assert interim != b""



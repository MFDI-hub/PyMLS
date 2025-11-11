from .data_structures import GroupContext
from ..crypto.crypto_provider import CryptoProvider


class KeySchedule:
    def __init__(self, init_secret: bytes, commit_secret: bytes, group_context: GroupContext, psk_secret: bytes | None, crypto_provider: CryptoProvider):
        self._init_secret = init_secret
        self._commit_secret = commit_secret
        self._group_context = group_context
        self._psk_secret = psk_secret
        self._crypto_provider = crypto_provider

        # Derive epoch secret
        # RFC-style joiner: init_secret || commit_secret (+ optional PSK)
        update_secret = self._crypto_provider.kdf_extract(self._init_secret, self._commit_secret)
        if self._psk_secret:
            update_secret = self._crypto_provider.kdf_extract(update_secret, self._psk_secret)
        hash_len = self._crypto_provider.kdf_hash_len()
        self._epoch_secret = self._crypto_provider.kdf_expand(update_secret, b"epoch", hash_len)

        # Derive key schedule branches
        self._handshake_secret = self._crypto_provider.kdf_expand(self._epoch_secret, b"handshake", hash_len)
        self._application_secret = self._crypto_provider.kdf_expand(self._epoch_secret, b"application", hash_len)
        self._exporter_secret = self._crypto_provider.kdf_expand(self._epoch_secret, b"exporter", hash_len)
        self._external_secret = self._crypto_provider.kdf_expand(self._epoch_secret, b"external", hash_len)

    def _derive_secret(self, label: bytes, length: int) -> bytes:
        return self._crypto_provider.kdf_expand(self._epoch_secret, label, length)

    @property
    def sender_data_secret(self) -> bytes:
        return self._derive_secret(b"sender data", self._crypto_provider.kdf_hash_len())

    def sender_data_key(self) -> bytes:
        return self._crypto_provider.kdf_expand(
            self.sender_data_secret, b"sender data key", self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce(self, reuse_guard: bytes) -> bytes:
        # Base nonce derived from sender_data_secret and XORed with a reuse guard (left-padded with zeros)
        base = self._crypto_provider.kdf_expand(
            self.sender_data_secret, b"sender data nonce", self._crypto_provider.aead_nonce_size()
        )
        rg = reuse_guard.rjust(self._crypto_provider.aead_nonce_size(), b"\x00")
        return bytes(a ^ b for a, b in zip(base, rg))

    @property
    def encryption_secret(self) -> bytes:
        return self._derive_secret(b"encryption", self._crypto_provider.kdf_hash_len())

    @property
    def exporter_secret(self) -> bytes:
        # Backed by explicit branch
        return self._exporter_secret

    def export(self, label: bytes, context: bytes, length: int) -> bytes:
        """
        Minimal exporter interface backed by exporter_secret.
        Not RFC-accurate but sufficient for DAVE sender-key derivation placeholder.
        """
        info = label + b"|" + context
        return self._crypto_provider.kdf_expand(self.exporter_secret, info, length)

    @property
    def confirmation_key(self) -> bytes:
        return self._derive_secret(b"confirm", self._crypto_provider.kdf_hash_len())

    @property
    def membership_key(self) -> bytes:
        return self._derive_secret(b"membership", self._crypto_provider.kdf_hash_len())

    @property
    def resumption_psk(self) -> bytes:
        return self._derive_secret(b"resumption", self._crypto_provider.kdf_hash_len())

    @property
    def handshake_secret(self) -> bytes:
        return self._handshake_secret

    @property
    def application_secret(self) -> bytes:
        return self._application_secret

    @property
    def external_secret(self) -> bytes:
        return self._external_secret

    @property
    def epoch_secret(self) -> bytes:
        return self._epoch_secret

    def derive_sender_secrets(self, leaf_index: int) -> tuple[bytes, bytes]:
        # This is a simplification. The real derivation uses a secret tree.
        handshake_secret = self.handshake_secret
        application_secret = self.application_secret
        return handshake_secret, application_secret

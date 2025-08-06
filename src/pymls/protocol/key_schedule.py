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
        update_secret = self._crypto_provider.kdf_extract(self._init_secret, self._commit_secret)
        if self._psk_secret:
            update_secret = self._crypto_provider.kdf_extract(update_secret, self._psk_secret)
        self._epoch_secret = self._crypto_provider.kdf_expand(update_secret, b"epoch", 32)

    def _derive_secret(self, label: bytes, length: int) -> bytes:
        return self._crypto_provider.kdf_expand(self._epoch_secret, label, length)

    @property
    def sender_data_secret(self) -> bytes:
        return self._derive_secret(b"sender data", 32)

    @property
    def encryption_secret(self) -> bytes:
        return self._derive_secret(b"encryption", 32)

    @property
    def exporter_secret(self) -> bytes:
        return self._derive_secret(b"exporter", 32)

    @property
    def confirmation_key(self) -> bytes:
        return self._derive_secret(b"confirm", 32)

    @property
    def membership_key(self) -> bytes:
        return self._derive_secret(b"membership", 32)

    @property
    def resumption_psk(self) -> bytes:
        return self._derive_secret(b"resumption", 32)

    def derive_sender_secrets(self, leaf_index: int) -> tuple[bytes, bytes]:
        # This is a simplification. The real derivation uses a secret tree.
        handshake_secret = self._derive_secret(b"handshake", 32)
        application_secret = self._derive_secret(b"application", 32)
        return handshake_secret, application_secret

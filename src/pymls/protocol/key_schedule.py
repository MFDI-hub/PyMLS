"""
Key schedule and labeled secret derivations.

Rationale:
- Implements RFC 9420 §9 (Secret Derivation) and §10 (Key Schedule) using
  ExpandWithLabel/DeriveSecret helpers provided by the CryptoProvider.
"""
from .data_structures import GroupContext
from ..crypto.crypto_provider import CryptoProvider


class KeySchedule:
    def __init__(self, init_secret: bytes, commit_secret: bytes, group_context: GroupContext, psk_secret: bytes | None, crypto_provider: CryptoProvider):
        self._init_secret = init_secret
        self._commit_secret = commit_secret
        self._group_context = group_context
        self._psk_secret = psk_secret
        self._crypto_provider = crypto_provider
        self._wiped = False

        # Derive epoch secret with RFC-labeled steps
        # update_secret := Extract(init_secret, commit_secret [+ psk])
        update_secret = self._crypto_provider.kdf_extract(self._init_secret, self._commit_secret)
        if self._psk_secret:
            update_secret = self._crypto_provider.kdf_extract(update_secret, self._psk_secret)
        hash_len = self._crypto_provider.kdf_hash_len()
        # epoch_secret := ExpandWithLabel(update_secret, "epoch", GroupContext, Hash.length)
        gc_bytes = self._group_context.serialize()
        self._epoch_secret = self._crypto_provider.expand_with_label(update_secret, b"epoch", gc_bytes, hash_len)

        # Derive key schedule branches using labeled derivations
        self._handshake_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"handshake")
        self._application_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"application")
        self._exporter_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"exporter")
        self._external_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"external")
        self._sender_data_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"sender data")

    @property
    def sender_data_secret(self) -> bytes:
        return self._sender_data_secret

    def sender_data_key(self) -> bytes:
        return self._crypto_provider.kdf_expand(
            self.sender_data_secret, b"sender data key", self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce(self, reuse_guard: bytes) -> bytes:
        # Base nonce derived from sender_data_secret and XORed with a reuse guard (left-padded with zeros)
        base = self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"sender data nonce", b"", self._crypto_provider.aead_nonce_size()
        )
        rg = reuse_guard.rjust(self._crypto_provider.aead_nonce_size(), b"\x00")
        return bytes(a ^ b for a, b in zip(base, rg))

    @property
    def encryption_secret(self) -> bytes:
        return self._crypto_provider.derive_secret(self._epoch_secret, b"encryption")

    @property
    def exporter_secret(self) -> bytes:
        # Backed by explicit branch
        return self._exporter_secret

    def export(self, label: bytes, context: bytes, length: int) -> bytes:
        return self._crypto_provider.expand_with_label(self.exporter_secret, label, context, length)

    @property
    def confirmation_key(self) -> bytes:
        return self._crypto_provider.derive_secret(self._epoch_secret, b"confirm")

    @property
    def membership_key(self) -> bytes:
        return self._crypto_provider.derive_secret(self._epoch_secret, b"membership")

    @property
    def resumption_psk(self) -> bytes:
        return self._crypto_provider.derive_secret(self._epoch_secret, b"resumption")

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
        """
        Deprecated helper: real per-sender secrets are derived via SecretTree (§9.2).
        Kept for compatibility; returns branch roots for diagnostics only.
        """
        handshake_secret = self.handshake_secret
        application_secret = self.application_secret
        return handshake_secret, application_secret

    def wipe(self) -> None:
        """
        Best-effort zeroization of sensitive secrets.
        """
        from ..crypto.utils import secure_wipe
        if self._wiped:
            return
        for name in [
            "_epoch_secret",
            "_handshake_secret",
            "_application_secret",
            "_exporter_secret",
            "_external_secret",
            "_sender_data_secret",
        ]:
            val = getattr(self, name, None)
            if isinstance(val, (bytes, bytearray)) and val:
                ba = bytearray(val)
                secure_wipe(ba)
        self._wiped = True

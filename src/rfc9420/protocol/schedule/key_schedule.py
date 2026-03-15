"""Key schedule and labeled secret derivations (RFC 9420 §8–§10).

Implements epoch secret derivation (init_secret, commit_secret, joiner_secret,
epoch_secret) and key schedule branches (encryption, exporter, external,
sender-data, init for next epoch) using ExpandWithLabel/DeriveSecret from
the CryptoProvider. Supports construction from full commit flow or from
Welcome (from_epoch_secret, from_joiner_secret).
"""
from typing import Optional
from ...messages.data_structures import GroupContext
from ...crypto.crypto_provider import CryptoProvider


class KeySchedule:
    """Derive epoch secrets and per-branch keys for an MLS group.

    This implementation follows RFC 9420 §9–§10 semantics using labels provided
    to the active CryptoProvider. It produces the epoch secret and branches for
    handshake, application, exporter, external, and sender-data, as well as
    helpers for confirmation, membership, resumption, and content encryption.
    """
    def __init__(self, init_secret: bytes, commit_secret: bytes, group_context: GroupContext, psk_secret: Optional[bytes], crypto_provider: CryptoProvider):
        """Construct a new key schedule for the current epoch.

        Parameters
        ----------
        init_secret : bytes
            Prior epoch's init secret (or 0 for the initial epoch).
        commit_secret : bytes
            The commit secret for the transition to this epoch.
        group_context : GroupContext
            Current GroupContext instance.
        psk_secret : Optional[bytes]
            Optional pre-shared key secret blended into update_secret.
        crypto_provider : CryptoProvider
            Active CryptoProvider exposing labeled KDFs.
        """
        self._group_context = group_context
        self._crypto_provider = crypto_provider
        self._wiped = False

        # Derive epoch secret with RFC-labeled steps (RFC 9420 §8)
        hash_len = self._crypto_provider.kdf_hash_len()
        gc_bytes = self._group_context.serialize()
        # Step 1: Extract(init_secret, commit_secret) — salt=init_secret, IKM=commit_secret
        pre_joiner = self._crypto_provider.kdf_extract(init_secret, commit_secret)
        # Step 2: joiner_secret (pre-PSK) — sent in Welcome; receiver blends PSK in from_joiner_secret
        joiner_secret_pre = self._crypto_provider.expand_with_label(pre_joiner, b"joiner", gc_bytes, hash_len)
        self._joiner_secret = joiner_secret_pre
        # Step 3: PSK blending (RFC 9420 §8, Figure 22): KDF.Extract always runs; use 0 when no PSK
        psk_or_zero = psk_secret if psk_secret else bytes(hash_len)
        blended = self._crypto_provider.kdf_extract(joiner_secret_pre, psk_or_zero)
        # epoch_secret := ExpandWithLabel(blended, "epoch", GroupContext, Hash.length)
        self._epoch_secret = self._crypto_provider.expand_with_label(blended, b"epoch", gc_bytes, hash_len)
        # welcome_secret = DeriveSecret(blended, "welcome") per RFC 9420 §8, Figure 22
        self._welcome_secret = self._crypto_provider.derive_secret(blended, b"welcome")

        # Derive key schedule branches using labeled derivations (RFC 9420 §8)
        self._encryption_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"encryption")
        self._exporter_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"exporter")
        self._external_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"external")
        self._sender_data_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"sender data")
        self._init_secret_derived = self._crypto_provider.derive_secret(self._epoch_secret, b"init")
        # Cache epoch-derived secrets (Table 4) to avoid recomputing on every access
        self._confirmation_key = self._crypto_provider.derive_secret(self._epoch_secret, b"confirm")
        self._membership_key = self._crypto_provider.derive_secret(self._epoch_secret, b"membership")
        self._resumption_psk = self._crypto_provider.derive_secret(self._epoch_secret, b"resumption")
        self._epoch_authenticator = self._crypto_provider.derive_secret(self._epoch_secret, b"authentication")

        # RFC 9420 §9.2: zero input and intermediate secrets after use
        from ...crypto.utils import secure_wipe
        for buf in (init_secret, commit_secret, pre_joiner):
            if buf:
                ba = bytearray(buf)
                secure_wipe(ba)
        if psk_secret:
            ba = bytearray(psk_secret)
            secure_wipe(ba)
        self._init_secret = b""
        self._commit_secret = b""
        self._psk_secret = None

    @classmethod
    def from_epoch_secret(cls, epoch_secret: bytes, group_context: GroupContext, crypto_provider: CryptoProvider) -> "KeySchedule":
        """Construct a KeySchedule when the epoch_secret is already known (e.g., from Welcome).

        Parameters
        ----------
        epoch_secret : bytes
            Epoch secret for this epoch.
        group_context : GroupContext
            Current GroupContext.
        crypto_provider : CryptoProvider
            Active CryptoProvider.

        Returns
        -------
        KeySchedule
            Key schedule derived from epoch secret.
        """
        ks: "KeySchedule" = object.__new__(cls)
        ks._init_secret = b""
        ks._commit_secret = b""
        ks._group_context = group_context
        ks._psk_secret = None
        ks._crypto_provider = crypto_provider
        ks._wiped = False
        ks._joiner_secret = b""
        ks._epoch_secret = epoch_secret
        ks._welcome_secret = b""
        ks._encryption_secret = crypto_provider.derive_secret(epoch_secret, b"encryption")
        ks._exporter_secret = crypto_provider.derive_secret(epoch_secret, b"exporter")
        ks._external_secret = crypto_provider.derive_secret(epoch_secret, b"external")
        ks._sender_data_secret = crypto_provider.derive_secret(epoch_secret, b"sender data")
        ks._init_secret_derived = crypto_provider.derive_secret(epoch_secret, b"init")
        ks._confirmation_key = crypto_provider.derive_secret(epoch_secret, b"confirm")
        ks._membership_key = crypto_provider.derive_secret(epoch_secret, b"membership")
        ks._resumption_psk = crypto_provider.derive_secret(epoch_secret, b"resumption")
        ks._epoch_authenticator = crypto_provider.derive_secret(epoch_secret, b"authentication")
        return ks

    @classmethod
    def from_joiner_secret(
        cls,
        joiner_secret: bytes,
        psk_secret: Optional[bytes],
        group_context: GroupContext,
        crypto_provider: CryptoProvider,
    ) -> "KeySchedule":
        """Construct a KeySchedule from joiner_secret (e.g., from Welcome processing).

        Parameters
        ----------
        joiner_secret : bytes
            Joiner secret from Welcome.
        psk_secret : Optional[bytes]
            Optional PSK secret.
        group_context : GroupContext
            Current GroupContext.
        crypto_provider : CryptoProvider
            Active CryptoProvider.

        Returns
        -------
        KeySchedule
            Key schedule derived from joiner secret.
        """
        hash_len = crypto_provider.kdf_hash_len()
        gc_bytes = group_context.serialize()
        psk_or_zero = psk_secret if psk_secret else bytes(hash_len)
        blended = crypto_provider.kdf_extract(joiner_secret, psk_or_zero)
        epoch_secret = crypto_provider.expand_with_label(blended, b"epoch", gc_bytes, hash_len)
        ks = cls.from_epoch_secret(epoch_secret, group_context, crypto_provider)
        ks._welcome_secret = crypto_provider.derive_secret(blended, b"welcome")
        return ks

    @property
    def sender_data_secret(self) -> bytes:
        """Sender data secret for this epoch.

        Returns
        -------
        bytes
            Sender data secret.
        """
        return self._sender_data_secret

    def sender_data_key(self) -> bytes:
        """Derive sender data encryption key.

        Returns
        -------
        bytes
            AEAD key for sender data.
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"key", b"", self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce(self, reuse_guard: bytes) -> bytes:
        """Derive sender data nonce with reuse guard.

        Parameters
        ----------
        reuse_guard : bytes
            Reuse guard (e.g. sequence number).

        Returns
        -------
        bytes
            AEAD nonce for sender data.
        """
        base = self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"nonce", b"", self._crypto_provider.aead_nonce_size()
        )
        rg = reuse_guard.rjust(self._crypto_provider.aead_nonce_size(), b"\x00")
        return bytes(a ^ b for a, b in zip(base, rg))

    def sender_data_key_from_sample(self, sample: bytes) -> bytes:
        """Derive sender data key from ciphertext sample.

        Parameters
        ----------
        sample : bytes
            Ciphertext sample for key derivation.

        Returns
        -------
        bytes
            AEAD key for sender data decryption.
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"key", sample, self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce_from_sample(self, sample: bytes, reuse_guard: bytes = b"") -> bytes:
        """Derive sender data nonce from sample.

        Parameters
        ----------
        sample : bytes
            Ciphertext sample.
        reuse_guard : bytes, optional
            Optional reuse guard (default b"").

        Returns
        -------
        bytes
            AEAD nonce.
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"nonce", sample, self._crypto_provider.aead_nonce_size()
        )

    @property
    def encryption_secret(self) -> bytes:
        return self._encryption_secret

    @property
    def exporter_secret(self) -> bytes:
        return self._exporter_secret

    def export(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export keying material (RFC 9420 exporter).

        Parameters
        ----------
        label : bytes
            Export label.
        context : bytes
            Context bytes.
        length : int
            Length of derived secret in bytes.

        Returns
        -------
        bytes
            Exported secret of requested length.
        """
        secret = self._crypto_provider.derive_secret(self.exporter_secret, label)
        context_hash = self._crypto_provider.hash(context)
        return self._crypto_provider.expand_with_label(secret, b"exported", context_hash, length)

    @property
    def confirmation_key(self) -> bytes:
        return self._confirmation_key

    @property
    def membership_key(self) -> bytes:
        return self._membership_key

    @property
    def resumption_psk(self) -> bytes:
        return self._resumption_psk

    @property
    def init_secret(self) -> bytes:
        return self._init_secret_derived

    @property
    def epoch_authenticator(self) -> bytes:
        return self._epoch_authenticator

    @property
    def external_secret(self) -> bytes:
        return self._external_secret

    @property
    def epoch_secret(self) -> bytes:
        return self._epoch_secret

    @property
    def joiner_secret(self) -> bytes:
        return self._joiner_secret

    @property
    def welcome_secret(self) -> bytes:
        return getattr(self, "_welcome_secret", b"")

    def wipe(self) -> None:
        """Zero all held secrets (RFC 9420 §9.2)."""
        from ...crypto.utils import secure_wipe
        if self._wiped:
            return
        for name in [
            "_epoch_secret",
            "_encryption_secret",
            "_exporter_secret",
            "_external_secret",
            "_sender_data_secret",
            "_init_secret_derived",
            "_confirmation_key",
            "_membership_key",
            "_resumption_psk",
            "_epoch_authenticator",
            "_welcome_secret",
        ]:
            val = getattr(self, name, None)
            if isinstance(val, (bytes, bytearray)) and val:
                ba = bytearray(val)
                secure_wipe(ba)
        self._wiped = True

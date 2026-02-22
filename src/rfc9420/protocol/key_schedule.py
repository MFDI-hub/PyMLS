"""Key schedule and labeled secret derivations (RFC 9420 §8–§10).

Implements epoch secret derivation (init_secret, commit_secret, joiner_secret,
epoch_secret) and key schedule branches (encryption, exporter, external,
sender-data, init for next epoch) using ExpandWithLabel/DeriveSecret from
the CryptoProvider. Supports construction from full commit flow or from
Welcome (from_epoch_secret, from_joiner_secret).
"""
from typing import Optional
from .data_structures import GroupContext
from ..crypto.crypto_provider import CryptoProvider


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
        - init_secret: Prior epoch's init secret (or 0 for the initial epoch).
        - commit_secret: The commit secret for the transition to this epoch.
        - group_context: Current GroupContext instance.
        - psk_secret: Optional pre-shared key secret blended into update_secret.
        - crypto_provider: Active CryptoProvider exposing labeled KDFs.
        """
        self._init_secret = init_secret
        self._commit_secret = commit_secret
        self._group_context = group_context
        self._psk_secret = psk_secret
        self._crypto_provider = crypto_provider
        self._wiped = False

        # Derive epoch secret with RFC-labeled steps (RFC 9420 §8)
        hash_len = self._crypto_provider.kdf_hash_len()
        gc_bytes = self._group_context.serialize()
        # Step 1: Extract(init_secret, commit_secret) — salt=init_secret, IKM=commit_secret
        pre_joiner = self._crypto_provider.kdf_extract(self._init_secret, self._commit_secret)
        # Step 2: joiner_secret = ExpandWithLabel(pre_joiner, "joiner", GroupContext, Nh)
        joiner_secret = self._crypto_provider.expand_with_label(pre_joiner, b"joiner", gc_bytes, hash_len)
        # Step 3: PSK blending — Extract(salt=joiner_secret, ikm=psk_secret) per RFC 9420 §8
        if self._psk_secret:
            joiner_secret = self._crypto_provider.kdf_extract(joiner_secret, self._psk_secret)
        self._joiner_secret = joiner_secret
        # epoch_secret := ExpandWithLabel(joiner_secret, "epoch", GroupContext, Hash.length)
        self._epoch_secret = self._crypto_provider.expand_with_label(joiner_secret, b"epoch", gc_bytes, hash_len)

        # Derive key schedule branches using labeled derivations (RFC 9420 §8)
        self._encryption_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"encryption")
        self._exporter_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"exporter")
        self._external_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"external")
        self._sender_data_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"sender data")
        self._init_secret_derived = self._crypto_provider.derive_secret(self._epoch_secret, b"init")

    @classmethod
    def from_epoch_secret(cls, epoch_secret: bytes, group_context: GroupContext, crypto_provider: CryptoProvider) -> "KeySchedule":
        """Construct a KeySchedule when the epoch_secret is already known (e.g., from Welcome).

        Derives all branch secrets from the provided epoch_secret and group_context.
        Does not compute joiner_secret or init_secret (used when joining via Welcome).

        Parameters:
            epoch_secret: Epoch secret for the new epoch.
            group_context: GroupContext for the epoch.
            crypto_provider: Crypto provider for labeled KDF.

        Returns:
            KeySchedule instance with all branch secrets derived.
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
        # Derive key schedule branches using labeled derivations (RFC 9420 §8)
        ks._encryption_secret = crypto_provider.derive_secret(epoch_secret, b"encryption")
        ks._exporter_secret = crypto_provider.derive_secret(epoch_secret, b"exporter")
        ks._external_secret = crypto_provider.derive_secret(epoch_secret, b"external")
        ks._sender_data_secret = crypto_provider.derive_secret(epoch_secret, b"sender data")
        ks._init_secret_derived = crypto_provider.derive_secret(epoch_secret, b"init")
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

        Per RFC 9420 §8: the joiner_secret is blended with psk_secret, then
        expanded to epoch_secret using the GroupContext. This is the proper way
        to derive the epoch in Welcome processing, rather than using
        joiner_secret as the epoch_secret directly.

        Parameters
        - joiner_secret: The joiner secret from the Welcome message.
        - psk_secret: Optional PSK secret for blending.
        - group_context: Current GroupContext to bind into.
        - crypto_provider: Active CryptoProvider.
        """
        hash_len = crypto_provider.kdf_hash_len()
        gc_bytes = group_context.serialize()
        # PSK blending: Extract(salt=joiner_secret, ikm=psk_secret) per RFC 9420 §8
        if psk_secret:
            blended = crypto_provider.kdf_extract(joiner_secret, psk_secret)
        else:
            blended = joiner_secret
        # epoch_secret = ExpandWithLabel(blended, "epoch", GroupContext, Nh)
        epoch_secret = crypto_provider.expand_with_label(blended, b"epoch", gc_bytes, hash_len)
        # Now construct from the derived epoch_secret
        return cls.from_epoch_secret(epoch_secret, group_context, crypto_provider)

    @property
    def sender_data_secret(self) -> bytes:
        """Base secret for deriving sender-data keys and nonces."""
        return self._sender_data_secret

    def sender_data_key(self) -> bytes:
        """Derive the AEAD key for SenderData protection.

        .. deprecated:: Use sender_data_key_from_sample for RFC-compliant derivation.
            This method uses empty context instead of ciphertext sample.
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"key", b"", self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce(self, reuse_guard: bytes) -> bytes:
        """Derive the AEAD nonce for SenderData, XORed with reuse_guard.

        .. deprecated:: Use sender_data_nonce_from_sample for RFC-compliant derivation.
            This method uses empty context instead of ciphertext sample.
        """
        base = self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"nonce", b"", self._crypto_provider.aead_nonce_size()
        )
        rg = reuse_guard.rjust(self._crypto_provider.aead_nonce_size(), b"\x00")
        return bytes(a ^ b for a, b in zip(base, rg))

    def sender_data_key_from_sample(self, sample: bytes) -> bytes:
        """Derive SenderData AEAD key per RFC 9420 §6.3.2.

        sender_data_key = ExpandWithLabel(sender_data_secret, "key", ciphertext_sample, AEAD.Nk)
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"key", sample, self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce_from_sample(self, sample: bytes, reuse_guard: bytes = b"") -> bytes:
        """Derive SenderData AEAD nonce per RFC 9420 §6.3.2.

        sender_data_nonce = ExpandWithLabel(sender_data_secret, "nonce", ciphertext_sample, Nn)

        Note: the reuse_guard is NOT XOR'd into the sender-data nonce. It is a
        field inside the SenderData plaintext and is XOR'd only into the content
        encryption nonce (MLSCiphertext.ciphertext nonce), not this nonce.
        The `reuse_guard` parameter is retained for API compatibility but is
        ignored.
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"nonce", sample, self._crypto_provider.aead_nonce_size()
        )

    @property
    def encryption_secret(self) -> bytes:
        """Epoch encryption secret feeding message protection contexts."""
        return self._encryption_secret

    @property
    def exporter_secret(self) -> bytes:
        # Backed by explicit branch
        """Epoch exporter secret for external key material derivations."""
        return self._exporter_secret

    def export(self, label: bytes, context: bytes, length: int) -> bytes:
        """Export external keying material from the exporter secret.
        
        RFC 9420 §8.5:
        MLS-Exporter(Label, Context, Length)
            = ExpandWithLabel(DeriveSecret(exporter_secret, Label), "exported", Hash(Context), Length)
        """
        secret = self._crypto_provider.derive_secret(self.exporter_secret, label)
        context_hash = self._crypto_provider.hash(context)
        return self._crypto_provider.expand_with_label(secret, b"exported", context_hash, length)

    @property
    def confirmation_key(self) -> bytes:
        """Key used to compute confirmation MACs over transcripts."""
        return self._crypto_provider.derive_secret(self._epoch_secret, b"confirm")

    @property
    def membership_key(self) -> bytes:
        """MAC key used for membership tags in handshake messages."""
        return self._crypto_provider.derive_secret(self._epoch_secret, b"membership")

    @property
    def resumption_psk(self) -> bytes:
        """Derive resumption PSK for future epochs."""
        return self._crypto_provider.derive_secret(self._epoch_secret, b"resumption")

    @property
    def init_secret(self) -> bytes:
        """DeriveSecret(epoch_secret, "init") per RFC 9420 §8.

        This is the init_secret used to chain into the next epoch's key schedule.
        """
        return self._init_secret_derived

    @property
    def epoch_authenticator(self) -> bytes:
        """Epoch authenticator secret (RFC §8)."""
        return self._crypto_provider.derive_secret(self._epoch_secret, b"authentication")

    @property
    def handshake_secret(self) -> bytes:
        """Deprecated: non-standard derivation kept for backward compatibility.

        RFC 9420 does not derive a separate handshake_secret from epoch_secret.
        The SecretTree handles handshake/application split from encryption_secret.
        """
        return self._crypto_provider.derive_secret(self._epoch_secret, b"handshake")

    @property
    def application_secret(self) -> bytes:
        """Deprecated: non-standard derivation kept for backward compatibility.

        RFC 9420 does not derive a separate application_secret from epoch_secret.
        The SecretTree handles handshake/application split from encryption_secret.
        """
        return self._crypto_provider.derive_secret(self._epoch_secret, b"application")

    @property
    def external_secret(self) -> bytes:
        """Secret for generating External Init and external commits (if used)."""
        return self._external_secret

    @property
    def epoch_secret(self) -> bytes:
        """The epoch secret from which all other secrets are derived."""
        return self._epoch_secret

    @property
    def joiner_secret(self) -> bytes:
        """The joiner secret used for Welcome message derivation."""
        return self._joiner_secret

    def wipe(self) -> None:
        """
        Best-effort zeroization of sensitive secrets.
        """
        from ..crypto.utils import secure_wipe
        if self._wiped:
            return
        for name in [
            "_epoch_secret",
            "_encryption_secret",
            "_exporter_secret",
            "_external_secret",
            "_sender_data_secret",
            "_init_secret_derived",
        ]:
            val = getattr(self, name, None)
            if isinstance(val, (bytes, bytearray)) and val:
                ba = bytearray(val)
                secure_wipe(ba)
        self._wiped = True

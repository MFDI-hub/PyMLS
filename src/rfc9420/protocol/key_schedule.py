"""
Key schedule and labeled secret derivations.

Rationale:
- Implements RFC 9420 §9 (Secret Derivation) and §10 (Key Schedule) using
  ExpandWithLabel/DeriveSecret helpers provided by the CryptoProvider.
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
        # Step 3: PSK blending — Extract(psk_secret, joiner_secret)
        if self._psk_secret:
            joiner_secret = self._crypto_provider.kdf_extract(self._psk_secret, joiner_secret)
        self._joiner_secret = joiner_secret
        # epoch_secret := ExpandWithLabel(joiner_secret, "epoch", GroupContext, Hash.length)
        self._epoch_secret = self._crypto_provider.expand_with_label(joiner_secret, b"epoch", gc_bytes, hash_len)

        # Derive key schedule branches using labeled derivations
        self._handshake_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"handshake")
        self._application_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"application")
        self._encryption_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"encryption")
        self._exporter_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"exporter")
        self._external_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"external")
        self._sender_data_secret = self._crypto_provider.derive_secret(self._epoch_secret, b"sender data")
        self._init_secret_derived = self._crypto_provider.derive_secret(self._epoch_secret, b"init")

    @classmethod
    def from_epoch_secret(cls, epoch_secret: bytes, group_context: GroupContext, crypto_provider: CryptoProvider) -> "KeySchedule":
        """
        Construct a KeySchedule when the epoch_secret is already known (e.g., from Welcome).
        Derives all branch secrets from the provided epoch_secret and group_context.
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
        # Derive key schedule branches using labeled derivations
        ks._handshake_secret = crypto_provider.derive_secret(epoch_secret, b"handshake")
        ks._application_secret = crypto_provider.derive_secret(epoch_secret, b"application")
        ks._encryption_secret = crypto_provider.derive_secret(epoch_secret, b"encryption")
        ks._exporter_secret = crypto_provider.derive_secret(epoch_secret, b"exporter")
        ks._external_secret = crypto_provider.derive_secret(epoch_secret, b"external")
        ks._sender_data_secret = crypto_provider.derive_secret(epoch_secret, b"sender data")
        ks._init_secret_derived = crypto_provider.derive_secret(epoch_secret, b"init")
        return ks
    @property
    def sender_data_secret(self) -> bytes:
        """Base secret for deriving sender-data keys and nonces."""
        return self._sender_data_secret

    def sender_data_key(self) -> bytes:
        """Derive the AEAD key for SenderData protection."""
        return self._crypto_provider.kdf_expand(
            self.sender_data_secret, b"sender data key", self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce(self, reuse_guard: bytes) -> bytes:
        """Derive the AEAD nonce for SenderData, XORed with reuse_guard.

        The reuse_guard is left-padded to the AEAD nonce size and XORed into
        the base nonce to mitigate nonce reuse.
        """
        # Base nonce derived from sender_data_secret and XORed with a reuse guard (left-padded with zeros)
        base = self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"sender data nonce", b"", self._crypto_provider.aead_nonce_size()
        )
        rg = reuse_guard.rjust(self._crypto_provider.aead_nonce_size(), b"\x00")
        return bytes(a ^ b for a, b in zip(base, rg))

    # --- RFC §6.3.2 SenderData derivation from ciphertext sample ---
    def sender_data_key_from_sample(self, sample: bytes) -> bytes:
        """
        Derive SenderData AEAD key from sender_data_secret and ciphertext sample.
        """
        return self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"sender data key", sample, self._crypto_provider.aead_key_size()
        )

    def sender_data_nonce_from_sample(self, sample: bytes, reuse_guard: bytes) -> bytes:
        """
        Derive SenderData AEAD nonce from sender_data_secret and ciphertext sample,
        then XOR in the reuse_guard (left-padded) per RFC to prevent nonce reuse.
        """
        base = self._crypto_provider.expand_with_label(
            self.sender_data_secret, b"sender data nonce", sample, self._crypto_provider.aead_nonce_size()
        )
        rg = reuse_guard.rjust(self._crypto_provider.aead_nonce_size(), b"\x00")
        return bytes(a ^ b for a, b in zip(base, rg))

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
        """Export external keying material from the exporter secret."""
        return self._crypto_provider.expand_with_label(self.exporter_secret, label, context, length)

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
        """Root for handshake traffic key derivations (via SecretTree)."""
        return self._handshake_secret

    @property
    def application_secret(self) -> bytes:
        """Root for application traffic key derivations (via SecretTree)."""
        return self._application_secret

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

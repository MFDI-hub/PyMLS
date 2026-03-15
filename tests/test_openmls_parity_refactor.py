from __future__ import annotations

import pytest

from rfc9420 import ProtocolMLSGroup, DefaultCryptoProvider
from rfc9420.codec.tls import TLSDecodeError, read_varint
from rfc9420.extensions.extensions import build_capabilities_data
from rfc9420.group.mls_group.processing import PendingCommit
from rfc9420.messages.data_structures import Credential, Signature
from rfc9420.messages.key_packages import KeyPackage, LeafNode
from rfc9420.messages.messages import SenderData
from rfc9420.mls.exceptions import (
    CommitValidationError,
    CryptoError,
    MalformedMessageError,
    NoPendingCommitError,
    ProtocolError,
    StateError,
)
from rfc9420.protocol.validations import CommitValidationError as ValidationCommitValidationError


class FixedRandProvider:
    def __init__(self, fill: int = 0x42):
        self._fill = fill
        self.calls: list[int] = []

    def random_bytes(self, length: int) -> bytes:
        self.calls.append(length)
        return bytes([self._fill]) * length


def _make_key_package(crypto: DefaultCryptoProvider) -> tuple[KeyPackage, bytes]:
    sig_sk, sig_pk = crypto.generate_key_pair()
    _kem_sk, kem_pk = crypto.generate_key_pair()
    caps = build_capabilities_data(
        ciphersuite_ids=[crypto.active_ciphersuite.suite_id],
        supported_exts=[],
        include_grease=False,
    )
    leaf = LeafNode(
        encryption_key=kem_pk,
        signature_key=sig_pk,
        credential=Credential(identity=b"user@example.test", public_key=sig_pk),
        capabilities=caps,
        parent_hash=b"",
    )
    kp = KeyPackage(leaf_node=leaf)
    sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", kp.tbs_serialize())
    return KeyPackage(leaf_node=leaf, signature=Signature(sig)), sig_sk


def test_rand_provider_injection_is_used_for_group_creation():
    crypto = DefaultCryptoProvider()
    rand = FixedRandProvider(fill=0xAA)
    kp, _sig_sk = _make_key_package(crypto)

    group = ProtocolMLSGroup.create(
        group_id=b"group-rand",
        key_package=kp,
        crypto_provider=crypto,
        rand_provider=rand,
    )

    assert group._key_schedule is not None
    assert group._key_schedule.epoch_secret == bytes([0xAA]) * crypto.kdf_hash_len()
    assert crypto.kdf_hash_len() in rand.calls


def test_state_transitions_and_state_persistence_roundtrip():
    crypto = DefaultCryptoProvider()
    rand = FixedRandProvider(fill=0xAB)
    kp, sig_sk = _make_key_package(crypto)
    group = ProtocolMLSGroup.create(
        group_id=b"group-state",
        key_package=kp,
        crypto_provider=crypto,
        rand_provider=rand,
    )

    pending = group.create_commit(sig_sk)
    assert group._state.value == "pending_commit_member"

    restored = ProtocolMLSGroup.from_bytes(
        group.to_bytes(),
        crypto,
        rand_provider=rand,
    )
    assert restored._state.value == "pending_commit_member"

    group.apply_own_commit(pending)
    assert group._state.value == "operational"


def test_apply_own_commit_without_pending_raises_state_error():
    crypto = DefaultCryptoProvider()
    rand = FixedRandProvider()
    kp, _sig_sk = _make_key_package(crypto)
    group = ProtocolMLSGroup.create(
        group_id=b"group-nopending",
        key_package=kp,
        crypto_provider=crypto,
        rand_provider=rand,
    )

    with pytest.raises(NoPendingCommitError):
        group.apply_own_commit(PendingCommit(None, [], {}))


def test_error_hierarchy_and_validation_aliasing():
    assert issubclass(CommitValidationError, ProtocolError)
    assert issubclass(TLSDecodeError, MalformedMessageError)
    assert issubclass(StateError, Exception)
    assert issubclass(CryptoError, Exception)
    assert ValidationCommitValidationError is CommitValidationError


def test_malformed_inputs_raise_structured_errors():
    with pytest.raises(MalformedMessageError):
        SenderData(sender=1, generation=1, reuse_guard=b"\x00").serialize()

    with pytest.raises(TLSDecodeError):
        read_varint(b"\xff", 0)

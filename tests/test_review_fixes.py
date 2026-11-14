"""Regression tests for confirmed protocol bugs.

Covers RequiredCapabilities encoding, per-leaf Update limits, PSK fail-closed
behavior, application-message signatures, secret-tree replay, GroupInfo signer
binding, and a two-member create/add/join/message flow.
"""

from __future__ import annotations

import os

import pytest

from rfc9420 import ProtocolMLSGroup, DefaultCryptoProvider
from rfc9420.codec.tls import write_uint16
from rfc9420.extensions.extensions import (
    GREASE_VALUES,
    build_required_capabilities,
    is_grease_value,
    parse_required_capabilities,
    build_capabilities_data,
)
from rfc9420.messages.data_structures import (
    Credential,
    PreSharedKeyID,
    PSKType,
    Sender,
    SenderType,
    Signature,
    UpdateProposal,
)
from rfc9420.messages.key_packages import KeyPackage, LeafNode
from rfc9420.messages.messages import (
    AuthenticatedContent,
    FramedContentAuthData,
    MLSPlaintext,
    attach_membership_tag,
)
from rfc9420.mls.exceptions import (
    CommitValidationError,
    InvalidSignatureError,
    RFC9420Error,
)
from rfc9420.protocol.tree.ratchet_tree import RatchetTree
from rfc9420.protocol.tree.secret_tree import SecretTree
from rfc9420.protocol.validations import validate_proposals_server_rules
from rfc9420.messages.messages import derive_psk_secret
from rfc9420.messages.data_structures import GroupInfo


def _member(crypto: DefaultCryptoProvider, identity: bytes):
    sig_sk = os.urandom(32)
    sig_pk = crypto.signature_public_from_private(sig_sk)
    enc_sk, enc_pk = crypto.generate_key_pair()
    init_sk, init_pk = crypto.generate_key_pair()
    caps = build_capabilities_data(
        ciphersuite_ids=[crypto.active_ciphersuite.suite_id],
        supported_exts=[],
        include_grease=False,
    )
    unsigned = LeafNode(
        encryption_key=enc_pk,
        signature_key=sig_pk,
        credential=Credential(identity=identity, public_key=sig_pk),
        capabilities=caps,
        lifetime_not_before=0,
        lifetime_not_after=(1 << 64) - 1,
    )
    leaf_sig = crypto.sign_with_label(sig_sk, b"LeafNodeTBS", unsigned.tbs_serialize())
    leaf = LeafNode(
        encryption_key=enc_pk,
        signature_key=sig_pk,
        credential=Credential(identity=identity, public_key=sig_pk),
        capabilities=caps,
        lifetime_not_before=0,
        lifetime_not_after=(1 << 64) - 1,
        signature=Signature(leaf_sig),
    )
    unsigned_kp = KeyPackage(init_key=init_pk, leaf_node=leaf)
    kp_sig = crypto.sign_with_label(sig_sk, b"KeyPackageTBS", unsigned_kp.tbs_serialize())
    kp = KeyPackage(init_key=init_pk, leaf_node=leaf, signature=Signature(kp_sig))
    return kp, sig_sk, init_sk, enc_sk


def test_required_capabilities_uses_varint_length_prefix():
    raw = build_required_capabilities([1, 2], [7], [])
    # 2 extension types * 2 bytes = 4, encoded as a one-byte varint, not a count.
    assert raw[0] == 4
    assert raw[1:5] == b"\x00\x01\x00\x02"
    exts, props, creds = parse_required_capabilities(raw)
    assert exts == [1, 2]
    assert props == [7]
    assert creds == []
    assert not raw.startswith(write_uint16(2) + write_uint16(1))


def test_grease_list_matches_rfc_9420():
    assert len(GREASE_VALUES) == 16
    assert 0xFAFA in GREASE_VALUES
    assert is_grease_value(0xFAFA)
    assert is_grease_value(0x0A0A)
    assert not is_grease_value(0x0A0B)
    assert not is_grease_value(0xFFFF)


def test_write_uint16_rejects_out_of_range():
    with pytest.raises(ValueError):
        write_uint16(0x10000)
    with pytest.raises(ValueError):
        write_uint16(-1)
    assert write_uint16(0x0102) == b"\x01\x02"


def test_two_updates_from_different_members_are_allowed():
    first = UpdateProposal(b"\x01")
    second = UpdateProposal(b"\x02")
    validate_proposals_server_rules(
        [first, second],
        committer_index=0,
        n_leaves=3,
        update_leaf_indices=[(first, 1), (second, 2)],
    )
    with pytest.raises(CommitValidationError, match="at most one Update"):
        validate_proposals_server_rules(
            [first, second],
            committer_index=0,
            n_leaves=3,
            update_leaf_indices=[(first, 1), (second, 1)],
        )


def test_missing_psk_value_fails_closed():
    crypto = DefaultCryptoProvider()
    psk_id = PreSharedKeyID(PSKType.EXTERNAL, psk_id=b"psk-name", psk_nonce=b"\x01" * 32)
    with pytest.raises(RFC9420Error, match="missing PSK"):
        derive_psk_secret(crypto, [psk_id], psk_values=None)
    with pytest.raises(RFC9420Error, match="missing PSK"):
        derive_psk_secret(crypto, [psk_id], psk_values=[None])


def test_consumed_application_generation_is_not_replayed():
    crypto = DefaultCryptoProvider()
    tree = SecretTree(os.urandom(crypto.kdf_hash_len()), crypto, n_leaves=1)
    _key, _nonce, generation = tree.next_application(0)
    tree.application_for(0, generation)
    with pytest.raises(ValueError, match="already consumed"):
        tree.application_for(0, generation)

    delayed = SecretTree(os.urandom(crypto.kdf_hash_len()), crypto, n_leaves=1)
    delayed.application_for(0, 1)
    delayed.application_for(0, 0)
    with pytest.raises(ValueError, match="already consumed"):
        delayed.application_for(0, 0)


def test_add_leaf_returns_leftmost_blank_not_last_index():
    crypto = DefaultCryptoProvider()
    tree = RatchetTree(crypto)

    def kp(tag: bytes) -> KeyPackage:
        leaf = LeafNode(
            encryption_key=tag,
            signature_key=tag + b"\xff",
            credential=Credential(identity=tag, public_key=tag + b"\xff"),
            capabilities=b"",
        )
        return KeyPackage(leaf_node=leaf)

    assert tree.add_leaf(kp(b"\x01")) == 0
    assert tree.add_leaf(kp(b"\x02")) == 1
    tree.remove_leaf(0)
    placed = tree.add_leaf(kp(b"\x03"))
    assert placed == 0
    assert placed != tree.n_leaves - 1


def test_two_party_join_and_signed_messages_roundtrip():
    crypto = DefaultCryptoProvider()
    alice_kp, alice_sk, _alice_init, _alice_enc = _member(crypto, b"alice")
    bob_kp, bob_sk, bob_init, bob_enc = _member(crypto, b"bob")

    alice = ProtocolMLSGroup.create(b"group-two-party", alice_kp, crypto)
    with pytest.raises(RFC9420Error, match="must be signed"):
        alice.protect(b"unsigned")

    proposal = alice.create_add_proposal(bob_kp, alice_sk)
    alice.process_proposal(proposal, Sender(0, SenderType.MEMBER))
    pending = alice.create_commit(alice_sk)
    assert pending.welcomes
    alice.apply_own_commit(pending)

    bob = ProtocolMLSGroup.from_welcome(
        pending.welcomes[0],
        bob_init,
        crypto,
        key_package=bob_kp,
        encryption_private_key=bob_enc,
    )
    assert bob.get_own_leaf_index() == 1
    assert bob.get_epoch() == alice.get_epoch()
    assert bob.get_epoch_authenticator() == alice.get_epoch_authenticator()

    to_bob = alice.protect(b"hello bob", alice_sk)
    assert bob.unprotect(to_bob) == (0, b"hello bob")
    with pytest.raises(ValueError, match="already consumed"):
        bob.unprotect(to_bob)

    to_alice = bob.protect(b"hello alice", bob_sk)
    assert alice.unprotect(to_alice) == (1, b"hello alice")

    with pytest.raises(CommitValidationError, match="key_package is required"):
        ProtocolMLSGroup.from_welcome(pending.welcomes[0], bob_init, crypto)


def test_replay_protection_survives_to_bytes():
    crypto = DefaultCryptoProvider()
    alice_kp, alice_sk, _alice_init, _alice_enc = _member(crypto, b"alice")
    bob_kp, _bob_sk, bob_init, bob_enc = _member(crypto, b"bob")
    alice = ProtocolMLSGroup.create(b"group-persist-replay", alice_kp, crypto)
    alice.process_proposal(
        alice.create_add_proposal(bob_kp, alice_sk),
        Sender(0, SenderType.MEMBER),
    )
    pending = alice.create_commit(alice_sk)
    alice.apply_own_commit(pending)
    bob = ProtocolMLSGroup.from_welcome(
        pending.welcomes[0],
        bob_init,
        crypto,
        key_package=bob_kp,
        encryption_private_key=bob_enc,
    )

    first = alice.protect(b"one", alice_sk)
    second = alice.protect(b"two", alice_sk)
    assert bob.unprotect(second) == (0, b"two")

    restored = ProtocolMLSGroup.from_bytes(bob.to_bytes(), crypto)
    assert restored.unprotect(first) == (0, b"one")
    with pytest.raises(ValueError, match="already consumed"):
        restored.unprotect(first)
    with pytest.raises(ValueError, match="already consumed"):
        restored.unprotect(second)

    alice_restored = ProtocolMLSGroup.from_bytes(alice.to_bytes(), crypto)
    third = alice_restored.protect(b"three", alice_sk)
    assert restored.unprotect(third) == (0, b"three")
    with pytest.raises(ValueError, match="already consumed"):
        restored.unprotect(third)


def test_same_credential_identity_is_allowed_unless_policy_enabled():
    crypto = DefaultCryptoProvider()
    alice_kp, alice_sk, _a_init, _a_enc = _member(crypto, b"alice")
    phone_kp, _phone_sk, _p_init, _p_enc = _member(crypto, b"bob")
    laptop_kp, _laptop_sk, _l_init, _l_enc = _member(crypto, b"bob")
    alice = ProtocolMLSGroup.create(b"group-multidevice", alice_kp, crypto)
    alice.process_proposal(
        alice.create_add_proposal(phone_kp, alice_sk),
        Sender(0, SenderType.MEMBER),
    )
    alice.process_proposal(
        alice.create_add_proposal(laptop_kp, alice_sk),
        Sender(0, SenderType.MEMBER),
    )
    pending = alice.create_commit(alice_sk)
    alice.apply_own_commit(pending)
    identities = [ident for _idx, ident in alice.get_member_identities() if ident]
    assert identities.count(b"bob") == 2

    alice.set_enforce_unique_credential_identities(True)
    tablet_kp, _t_sk, _t_init, _t_enc = _member(crypto, b"bob")
    alice.process_proposal(
        alice.create_add_proposal(tablet_kp, alice_sk),
        Sender(0, SenderType.MEMBER),
    )
    with pytest.raises(CommitValidationError, match="duplicate credential identity"):
        alice.create_commit(alice_sk)


def test_groupinfo_signature_is_bound_to_signer_leaf():
    crypto = DefaultCryptoProvider()
    alice_kp, alice_sk, _init, _enc = _member(crypto, b"alice")
    bob_kp, bob_sk, bob_init, bob_enc = _member(crypto, b"bob")
    alice = ProtocolMLSGroup.create(b"group-gi", alice_kp, crypto)
    alice.process_proposal(
        alice.create_add_proposal(bob_kp, alice_sk), Sender(0, SenderType.MEMBER)
    )
    pending = alice.create_commit(alice_sk)
    alice.apply_own_commit(pending)
    bob = ProtocolMLSGroup.from_welcome(
        pending.welcomes[0],
        bob_init,
        crypto,
        key_package=bob_kp,
        encryption_private_key=bob_enc,
    )
    gi = GroupInfo.deserialize(alice.export_group_info(alice_sk))
    forged = GroupInfo(
        gi.group_context,
        gi.signature,
        gi.extensions,
        gi.confirmation_tag,
        signer_leaf_index=bob.get_own_leaf_index(),
    )
    with pytest.raises(InvalidSignatureError):
        ProtocolMLSGroup.from_group_info(forged, crypto)


def test_failed_commit_does_not_corrupt_the_group():
    crypto = DefaultCryptoProvider()
    alice_kp, alice_sk, _a_init, _a_enc = _member(crypto, b"alice")
    bob_kp, bob_sk, bob_init, bob_enc = _member(crypto, b"bob")
    alice = ProtocolMLSGroup.create(b"group-atomic", alice_kp, crypto)
    alice.process_proposal(
        alice.create_add_proposal(bob_kp, alice_sk), Sender(0, SenderType.MEMBER)
    )
    pending = alice.create_commit(alice_sk)
    alice.apply_own_commit(pending)
    bob = ProtocolMLSGroup.from_welcome(
        pending.welcomes[0],
        bob_init,
        crypto,
        key_package=bob_kp,
        encryption_private_key=bob_enc,
    )
    spare = alice.protect(b"still good", alice_sk)
    epoch = bob.get_epoch()
    authenticator = bob.get_epoch_authenticator()

    update = alice.create_commit(alice_sk)
    original = update.commit_message
    bad_auth = FramedContentAuthData(
        signature=original.auth_content.signature,
        confirmation_tag=b"\x00" * crypto.kdf_hash_len(),
    )
    bad = MLSPlaintext(
        AuthenticatedContent(
            tbs=original.auth_content.tbs,
            auth=bad_auth,
            membership_tag=None,
        )
    )
    bad = attach_membership_tag(bad, alice._key_schedule.membership_key, crypto)
    with pytest.raises(CommitValidationError, match="invalid confirmation tag"):
        bob.process_commit(bad, 0)
    assert bob.get_epoch() == epoch
    assert bob.get_epoch_authenticator() == authenticator
    assert bob.unprotect(spare) == (0, b"still good")

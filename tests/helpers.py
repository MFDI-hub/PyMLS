from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from rfc9420 import DefaultCryptoProvider, Group
from rfc9420.protocol.data_structures import Credential, Signature
from rfc9420.protocol.key_packages import KeyPackage, LeafNode, LeafNodeSource


@dataclass
class MemberMaterial:
    key_package: KeyPackage
    hpke_private_key: bytes
    signing_private_key: bytes


def has_hpke() -> bool:
    try:
        from rfc9180 import AEADID, HPKE, KDFID, KEMID  # noqa: F401
    except Exception:
        return False
    return True


def _ed25519_keypair() -> tuple[bytes, bytes]:
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()


def _x25519_keypair() -> tuple[bytes, bytes]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk.private_bytes_raw(), pk.public_bytes_raw()


def make_member(identity: bytes, crypto: DefaultCryptoProvider | None = None) -> MemberMaterial:
    crypto = crypto or DefaultCryptoProvider()

    _, leaf_hpke_pk = _x25519_keypair()
    init_hpke_sk, init_hpke_pk = _x25519_keypair()  # keep init_key != leaf.encryption_key
    sign_sk, sign_pk = _ed25519_keypair()
    now = int(time.time())

    leaf_unsigned = LeafNode(
        encryption_key=leaf_hpke_pk,
        signature_key=sign_pk,
        credential=Credential(identity=identity, public_key=sign_pk),
        capabilities=b"",
        leaf_node_source=LeafNodeSource.KEY_PACKAGE,
        lifetime_not_before=max(0, now - 3600),
        lifetime_not_after=now + 3600 * 24,
        signature=b"",
    )
    leaf_sig = crypto.sign_with_label(sign_sk, b"LeafNodeTBS", leaf_unsigned.tbs_serialize())
    leaf = LeafNode(
        encryption_key=leaf_unsigned.encryption_key,
        signature_key=leaf_unsigned.signature_key,
        credential=leaf_unsigned.credential,
        capabilities=leaf_unsigned.capabilities,
        leaf_node_source=leaf_unsigned.leaf_node_source,
        lifetime_not_before=leaf_unsigned.lifetime_not_before,
        lifetime_not_after=leaf_unsigned.lifetime_not_after,
        parent_hash=leaf_unsigned.parent_hash,
        extensions=leaf_unsigned.extensions,
        signature=leaf_sig,
    )

    kp_unsigned = KeyPackage(
        init_key=init_hpke_pk,
        leaf_node=leaf,
        extensions=[],
        signature=Signature(b""),
    )
    kp_sig = crypto.sign_with_label(sign_sk, b"KeyPackageTBS", kp_unsigned.tbs_serialize())
    kp = KeyPackage(
        version=kp_unsigned.version,
        cipher_suite=kp_unsigned.cipher_suite,
        init_key=kp_unsigned.init_key,
        leaf_node=kp_unsigned.leaf_node,
        extensions=kp_unsigned.extensions,
        signature=Signature(kp_sig),
    )

    return MemberMaterial(
        key_package=kp,
        hpke_private_key=init_hpke_sk,
        signing_private_key=sign_sk,
    )


def make_group(
    group_id: bytes = b"test-group",
) -> tuple[Group, MemberMaterial, DefaultCryptoProvider]:
    crypto = DefaultCryptoProvider()
    member = make_member(b"member-a", crypto)
    group = Group.create(group_id, member.key_package, crypto)
    return group, member, crypto

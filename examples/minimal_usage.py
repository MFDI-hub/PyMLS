from pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from pymls.protocol.mls_group import MLSGroup
from pymls.protocol.key_packages import KeyPackage, LeafNode
from pymls.protocol.data_structures import Credential, Signature


def main():
    crypto = DefaultCryptoProvider()
    # Create an initial key package for the creator
    sk_sig = crypto.sign  # placeholder for signature key mgmt
    enc_sk, enc_pk = crypto.generate_key_pair()
    sig_sk = b"\x11" * 32  # placeholder secret; use real key mgmt
    sig_pk = b"\x22" * 32  # placeholder public
    cred = Credential(identity=b"user-1", public_key=sig_pk)
    leaf = LeafNode(encryption_key=enc_pk, signature_key=sig_pk, credential=cred, capabilities=b"", parent_hash=b"")
    kp = KeyPackage(leaf_node=leaf, signature=Signature(b""))

    group = MLSGroup.create(b"group-1", kp, crypto)
    print("Group created, epoch:", group.get_epoch())


if __name__ == "__main__":
    main()



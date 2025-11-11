import asyncio

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.pymls.crypto.default_crypto_provider import DefaultCryptoProvider
from src.pymls.dave.session_manager import DaveSessionManager
from src.pymls.dave.media_transform import FrameEncryptor, FrameDecryptor


async def main():
    crypto = DefaultCryptoProvider()

    # Ed25519 for signatures
    sk_ed = Ed25519PrivateKey.generate()
    pk_ed = sk_ed.public_key()
    sig_sk = sk_ed.private_bytes_raw()
    sig_pk = pk_ed.public_bytes_raw()

    # X25519 for KEM
    kem_sk, kem_pk = crypto.generate_key_pair()

    # Replace with your Voice Gateway send functions
    async def send_json(d: dict):
        print("send_json:", d)

    async def send_binary(b: bytes):
        print("send_binary:", len(b), "bytes")

    mgr = DaveSessionManager(
        crypto=crypto,
        self_user_id="123",
        send_json=send_json,
        send_binary=send_binary,
        signature_private_key=sig_sk,
        signature_public_key=sig_pk,
        kem_private_key=kem_sk,
        kem_public_key=kem_pk,
    )

    await mgr.on_select_protocol_ack("1.1.4")
    await mgr.on_protocol_prepare_epoch(transition_id=1)

    # In a real app, forward mgr's binary outputs to the Voice Gateway and pass
    # incoming DAVE binary opcodes to mgr.on_mls_binary(...).

    # Media transform usage (demonstration only):
    encryptor = FrameEncryptor(crypto, mgr.sender_keys)
    # Ensure sender keys exist for this user (normally from Welcome/epoch change)
    mgr.set_recognized_users({"123"})
    mgr._refresh_sender_ratchets()

    # Encrypt/decrypt a dummy OPUS frame
    user_id_int = int("123")
    frame = b"\xF8" * 20  # synthetic opus-like payload
    out = encryptor.encrypt_opus_frame(user_id_int, frame)
    key, nonce = mgr.sender_keys.ratchets[user_id_int].derive_for_generation(0)
    decrypted = FrameDecryptor(crypto).decrypt_opus_frame(key, nonce, out)
    assert decrypted == frame
    print("OPUS frame round-trip OK")


if __name__ == "__main__":
    asyncio.run(main())


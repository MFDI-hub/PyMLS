# DAVE integration with pymls

This document outlines how to drive the DAVE protocol (v1.1.x) on top of `pymls` using the asyncio session manager.

## Components

- `pymls.crypto.constants.DAVE_MLS_CIPHERSUITE`: MLS ciphersuite (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`).
- `pymls.dave.codec`: Binary codec for DAVE opcodes 25–30, helpers for 21–24/31 JSON.
- `pymls.dave.session_manager.DaveSessionManager`: Async state machine handling DAVE MLS opcodes.
- `pymls.dave.ratchet`: Per-sender key derivation and ratchets.
- `pymls.dave.media_transform`: OPUS frame encrypt/decrypt using AES-128-GCM and a simple framing.

## Minimal lifecycle

1. Construct `DaveSessionManager` with crypto provider, identity and keys.
2. After `select_protocol_ack`, call `on_protocol_prepare_epoch(transition_id)`.
3. Send the resulting KeyPackage (opcode 26) via your Voice Gateway connection.
4. When you receive a Welcome (opcode 30) or Commit/Welcome union (opcode 28), call `on_mls_binary(bytes)` with the packet.
5. After an epoch change, `DaveSessionManager` refreshes sender ratchets for recognized users.
6. Use `FrameEncryptor/FrameDecryptor` from `media_transform` to protect OPUS frames with per-sender keys.

## Example

See `examples/minimal_voice.py`.


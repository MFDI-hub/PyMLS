RFC 9420 Compliance Changes (v0.2.0)

This release updates PyMLS to align more closely with RFC 9420 in several areas.

Breaking change

- Update Path Derivation: Internode keys on an update path are now derived using a top‑down path_secret construction (RFC §7.4). A single fresh path_secret is generated at the leaf and ratcheted upward with DeriveSecret(..., "path"). Each node key pair is deterministically derived from DeriveSecret(path_secret, "node"). This replaces the previous strategy of generating fresh key pairs and extracting secrets from private keys.

Enhancements

- Deterministic KEM DeriveKeyPair: Implements deterministic derivation for DHKEM X25519/X448 (with clamping) and for P‑256/P‑521 via modular reduction, wired into ratchet path processing.
- Proposal Ordering: Commit creation now partitions and orders proposals according to RFC §12.3 (GroupContextExtensions → Update → Remove → Add → PreSharedKey). ReInit proposals remain exclusive.
- PSK Handling: PSK proposals are bound via a commit binder and integrated into the epoch key schedule when present.
- Transcript Bootstrap: The interim transcript hash is initialized at group creation using an all‑zero confirmation tag per RFC §11.
- Secret Tree window: Out-of-order receive support via a sliding skipped-keys window is enabled by default (128). Configure with `MLSGroup(..., secret_tree_window_size=128)` or `SecretTree(..., window_size=128)`.
- Ratchet Tree truncation: The tree now truncates immediately after Remove if the rightmost leaves are blank (normative RFC §7.7), reducing sparse tails and aligning tree hash expectations.

Notes

- GroupContextExtensions proposals are accepted and ordered. Their data is merged into GroupInfo extensions for Welcomes; the GroupContext structure in this codebase remains minimal and does not store extensions explicitly.

Migration guidance

- Groups created with previous versions that expect the legacy update‑path derivation are not wire‑compatible. Recreate groups or re‑onboard members using new Welcomes.



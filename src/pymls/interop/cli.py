from __future__ import annotations

import argparse
from .harness import (
    export_plaintext_hex,
    import_plaintext_hex,
    export_ciphertext_hex,
    import_ciphertext_hex,
    export_handshake_b64,
    import_handshake_b64,
    export_application_b64,
    import_application_b64,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pymls-interop")
    sub = p.add_subparsers(dest="cmd", required=True)
    pt = sub.add_parser("plaintext")
    pt_sub = pt.add_subparsers(dest="op", required=True)
    d1 = pt_sub.add_parser("decode")
    d1.add_argument("hex")
    ct = sub.add_parser("ciphertext")
    ct_sub = ct.add_subparsers(dest="op", required=True)
    d2 = ct_sub.add_parser("decode")
    d2.add_argument("hex")
    # RFC wire helpers (base64)
    wire = sub.add_parser("wire")
    wire_sub = wire.add_subparsers(dest="op", required=True)
    w1 = wire_sub.add_parser("encode-handshake")
    w1.add_argument("hex")  # input: hex-encoded MLSPlaintext to convert to base64 wire
    w2 = wire_sub.add_parser("decode-handshake")
    w2.add_argument("b64")  # input: base64 TLS presentation bytes → hex MLSPlaintext
    w3 = wire_sub.add_parser("encode-application")
    w3.add_argument("hex")  # input: hex-encoded MLSCiphertext → base64 wire
    w4 = wire_sub.add_parser("decode-application")
    w4.add_argument("b64")  # input: base64 TLS presentation bytes → hex MLSCiphertext
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    if args.cmd == "plaintext" and args.op == "decode":
        m = import_plaintext_hex(args.hex)
        print(export_plaintext_hex(m))
        return 0
    if args.cmd == "ciphertext" and args.op == "decode":
        m = import_ciphertext_hex(args.hex)
        print(export_ciphertext_hex(m))
        return 0
    if args.cmd == "wire" and args.op == "encode-handshake":
        m = import_plaintext_hex(args.hex)
        print(export_handshake_b64(m))
        return 0
    if args.cmd == "wire" and args.op == "decode-handshake":
        m = import_handshake_b64(args.b64)
        print(export_plaintext_hex(m))
        return 0
    if args.cmd == "wire" and args.op == "encode-application":
        m = import_ciphertext_hex(args.hex)
        print(export_application_b64(m))
        return 0
    if args.cmd == "wire" and args.op == "decode-application":
        m = import_application_b64(args.b64)
        print(export_ciphertext_hex(m))
        return 0
    return 2



from __future__ import annotations

import argparse
from .harness import export_plaintext_hex, import_plaintext_hex, export_ciphertext_hex, import_ciphertext_hex


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
    return 2



#!/usr/bin/env python3
"""Position-dependent XOR encoder for FwPolicySvc.cs string literals.

Formula (identical to the other q3-plan C# payloads, e.g. EfsPotato / NtdsRawDump):

    encoded[i] = plaintext[i] ^ ((0xA3 + i * 0x5B) & 0xFF)

The position-dependent key means no single constant can be recovered by
single-byte brute-force (FLOSS, CyberChef, etc.). Use this script to (re)generate
the C# byte-array literals embedded in class `X`.

Usage:
    python encode.py                          # emit the default ProgID literals
    python encode.py <field> <plaintext>      # emit one literal, e.g.:
    python encode.py _policy2 "HNetCfg.FwPolicy2"
    python encode.py --verify                 # round-trip check of the defaults
"""

import sys

DEFAULTS = [
    ("_policy2", "HNetCfg.FwPolicy2"),
    ("_fwrule", "HNetCfg.FwRule"),
]


def _key(i: int) -> int:
    return (0xA3 + i * 0x5B) & 0xFF


def encode(s: str) -> bytes:
    return bytes(c ^ _key(i) for i, c in enumerate(s.encode("ascii")))


def decode(b: bytes) -> str:
    return bytes(c ^ _key(i) for i, c in enumerate(b)).decode("ascii")


def literal(field: str, plaintext: str) -> str:
    body = ", ".join("0x%02X" % x for x in encode(plaintext))
    return "internal static readonly byte[] %s = new byte[] { %s };" % (field, body)


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--verify":
        ok = True
        for field, plain in DEFAULTS:
            enc = encode(plain)
            back = decode(enc)
            status = "OK" if back == plain else "MISMATCH"
            ok = ok and back == plain
            print("%-10s %-18s %s -> %s" % (field, plain, status, back))
        return 0 if ok else 1

    if len(sys.argv) == 3:
        print(literal(sys.argv[1], sys.argv[2]))
        return 0

    for field, plain in DEFAULTS:
        print(literal(field, plain))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

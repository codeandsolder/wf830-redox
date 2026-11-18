"""Validate the guest P4 liblted.so callback images against recovered ABI.

Only the *input HCI responses* are test-derived. The image bytes were
observed from the actual OEM callback function under qemu-armeb.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

BASE = Path(os.environ["WF830_ORACLE_WORK_DIR"]) / "logs"


def checked(label: str, data: bytes, offset: int, expected: bytes) -> None:
    actual = data[offset:offset + len(expected)]
    assert actual == expected, (
        f"{label} offset=0x{offset:x}: actual {actual.hex()} expected {expected.hex()}"
    )


def check_family(family: str) -> dict:
    p = BASE / f"{family}-image.bin"
    data = p.read_bytes()
    checks: list[tuple[int, bytes]]
    if family == "attach":
        assert len(data) == 0x88b
        checks = [
            (0, bytes.fromhex("0001000212345678090a")),
            (0xa, bytes([3])),
            (0xb, b"ims"),
            (0x4b, b"pdn"),
            (0xcb, bytes([2])),
            (0xcc, bytes.fromhex("deadbeef")),
            (0xd0, bytes([192, 168, 1, 2])),
            (0x261, (9).to_bytes(4, "big")),
            (0x275, bytes([1, 2, 3, 4, 5])),
            (0x27a, bytes([1])),
            (0x27b, bytes.fromhex("aabbcc")),
            (0x27e, (1500).to_bytes(2, "big")),
            (0x280, bytes.fromhex("0103112233")),
            (0x2e6, (0x01020304).to_bytes(4, "big")),
            (0x2ea, (100).to_bytes(4, "big")),
            (0x2ee, (200).to_bytes(4, "big")),
            (0x2f2, bytes([1])),
            (0x2f3, bytes([4, 9]) + b"112"),
            (0x875, bytes([5]) + b"12345"),
        ]
        assert data[0x87b:] == bytes(len(data) - 0x87b)
    elif family == "pdn":
        assert len(data) == 0x2e6
        checks = [
            (0, bytes.fromhex("0001000200031234090a")),
            (0xa, bytes([1])),
            (0xb, bytes([3])),
            (0xc, b"ims"),
            (0x4c, b"pdn"),
            (0xcc, bytes([2])),
            (0xd1, bytes([192, 168, 1, 2])),
            (0xd5, bytes([1, 1, 1, 1])),
            (0x262, (9).to_bytes(4, "big")),
            (0x276, (1500).to_bytes(2, "big")),
            (0x278, bytes.fromhex("0103112233")),
            (0x2de, (100).to_bytes(4, "big")),
            (0x2e2, (200).to_bytes(4, "big")),
        ]
    elif family == "plmn":
        assert len(data) == 436
        checks = [
            (0, bytes.fromhex("000000000262f0100011001efe000312340000189caabb01234567")),
            (27, (1).to_bytes(4, "big")),
            (31, bytes.fromhex("62f010")),
            (34, (1).to_bytes(4, "big")),
            (38, (2).to_bytes(4, "big")),
            (383, (7).to_bytes(4, "big")),
            (387, bytes([1])),
            (388, bytes.fromhex("62f010")),
        ]
        assert data[42:383] == bytes(341)
        assert data[391:] == bytes(len(data) - 391)
    elif family == "rrc-set":
        assert data == bytes.fromhex("000000010007")
        checks = []
    elif family == "rrc-get":
        assert data == bytes.fromhex("000000070001bb")
        checks = []
    else:
        raise ValueError(f"unsupported family {family}")
    for offset, pattern in checks:
        checked(family, data, offset, pattern)
    return {
        "family": family,
        "bytes": len(data),
        "field_checks": len(checks),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    family = sys.argv[1]
    subfamilies = ["rrc-set", "rrc-get"] if family == "rrc" else [family]
    summaries = [check_family(subfamily) for subfamily in subfamilies]
    print(json.dumps(summaries, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

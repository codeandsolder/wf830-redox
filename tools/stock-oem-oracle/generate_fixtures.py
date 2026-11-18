"""Extract synthetic modem response vectors from the Rust ABI golden tests.

These are *not* live captures. Extraction fails if the test stops containing
an explicit byte-list literal, rather than fabricating a replacement.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

FIXTURES = {
    "attach": (
        "attach_response_materializes_exact_stock_callback_and_subscription_gate",
        0xB102,
    ),
    "pdn": (
        "pdn_connect_response_materializes_exact_stock_callback_and_subscription_gate",
        0xB106,
    ),
    "plmn": (
        "plmn_search_response_materializes_exact_stock_callback_and_subscription_gate",
        0xB10A,
    ),
}
INTEGER = re.compile(r"(?:0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)")
BYTE_LITERAL = re.compile(r"b'(?:[^'\\]|\\.)+'")


def payload_for_test(source: str, name: str) -> bytes:
    signature = f"fn {name}()"
    if source.count(signature) != 1:
        raise ValueError(f"missing or ambiguous test {name}")
    body = source.split(signature, 1)[1].split("\n#[test]", 1)[0]
    if body.count("let payload = [") != 1:
        raise ValueError(f"expected exactly one payload literal in {name}")
    raw = body.split("let payload = [", 1)[1].split("];", 1)[0]
    raw = re.sub(r"//[^\n]*", "", raw)
    result: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        if INTEGER.fullmatch(item):
            n = int(item.replace("_", ""), 0) if item.lower().startswith("0x") else int(
                item.replace("_", ""), 10
            )
        elif BYTE_LITERAL.fullmatch(item):
            literal = ast.literal_eval(item)
            if not isinstance(literal, bytes) or len(literal) != 1:
                raise ValueError(f"not a one-byte literal: {item}")
            n = literal[0]
        else:
            raise ValueError(f"unsupported fixture token {item!r} in {name}")
        if not 0 <= n <= 255:
            raise ValueError(f"out-of-range byte {n} in {name}")
        result.append(n)
    return bytes(result)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: generate_fixtures.py RUST_TESTS_RS OUTPUT_DIR")
    source_file = Path(sys.argv[1])
    out = Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    source = source_file.read_text()
    manifest = {
        "source": str(source_file),
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "provenance": "synthetic vectors from in-repository Rust golden tests, not live HCI captures",
        "fixtures": {},
    }
    for family, (name, opcode) in FIXTURES.items():
        payload = payload_for_test(source, name)
        wire = struct.pack(">HH", opcode, len(payload)) + payload
        path = out / f"{family}-response-test-fixture.bin"
        path.write_bytes(wire)
        manifest["fixtures"][family] = {
            "test": name,
            "opcode": f"0x{opcode:04x}",
            "payload_bytes": len(payload),
            "sha256": hashlib.sha256(wire).hexdigest(),
        }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest["fixtures"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

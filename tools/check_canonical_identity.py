#!/usr/bin/env python3
"""Canonicalise every JSON object under a directory with both the RFC 8785
canonicaliser and the legacy sorted-json encoding, and report any digest that
differs. Exit 0 when none differ.

    python3 tools/check_canonical_identity.py examples/out

Kept so the claim that RFC 8785 changed no byte of the examples can be
re-run rather than remembered.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dr.canonical import canonical_bytes, legacy_sorted_json_bytes, read_jsonl  # noqa: E402


def objects(root: Path):
    for path in sorted(root.rglob("*")):
        if path.suffix == ".json":
            yield path, None, json.loads(path.read_text(encoding="utf-8"))
        elif path.suffix == ".jsonl":
            for i, line in read_jsonl(path):
                yield path, i, json.loads(line)


def main(argv) -> int:
    root = Path(argv[1] if len(argv) > 1 else "examples/out")
    total = differ = 0
    for path, line, obj in objects(root):
        total += 1
        a, b = canonical_bytes(obj), legacy_sorted_json_bytes(obj)
        if a != b:
            differ += 1
            where = f"{path}:{line}" if line else str(path)
            print(f"DIFFERS {where}")
    print(f"{total} objects canonicalised under both encodings; {differ} differ")
    return 1 if differ else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

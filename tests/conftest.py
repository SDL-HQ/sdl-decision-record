from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dr.emit import RECORD_FILE, Run  # noqa: E402
from dr.signing import generate_private_key_pem, public_key_pem, sign_record  # noqa: E402
from dr.verify import Report, verify_directory  # noqa: E402
from emitters import classrouter, ratelimit, toolgate  # noqa: E402

TOOL_POLICY = {"tools": {"get_weather": {"args": {"city": "string"}}, "lookup_order": {"args": {"order_id": "integer"}}}}
TOOL_SUITE: List[Dict[str, Any]] = [
    {"input": {"tool": "get_weather", "args": {"city": "Auckland"}}, "label": "ALLOW"},
    {"input": {"tool": "lookup_order", "args": {"order_id": 7}}, "label": "ALLOW"},
    {"input": {"tool": "delete_everything", "args": {}}, "label": "DENY"},
    {"input": {"tool": "lookup_order", "args": {"order_id": "7"}}, "label": "DENY"},
    {"input": {"tool": "get_weather", "args": {"city": "Auckland", "extra": 1}}, "label": "DENY"},
]


@pytest.fixture
def keys(tmp_path: Path):
    pem = generate_private_key_pem()
    reg = {"registry_version": 1, "keys": [{"key_id": "k1", "status": "active", "public_key_pem": public_key_pem(pem)}]}
    reg_path = tmp_path / "registry.json"
    reg_path.write_text(json.dumps(reg))
    return {"pem": pem, "registry": reg_path, "registry_obj": reg, "key_id": "k1"}


def build_run(
    directory: Path,
    keys,
    *,
    module=toolgate,
    policy=None,
    items: Optional[List[Dict[str, Any]]] = None,
    labelled: bool = True,
    retain_inputs: bool = True,
    record_id: str = "r1",
    **run_kwargs,
) -> Path:
    policy = policy if policy is not None else TOOL_POLICY
    items = items if items is not None else TOOL_SUITE
    decider = module.Decider(policy)
    run = Run(directory, decider_id=module.DECIDER_ID, decider_version=module.DECIDER_VERSION, outcomes=module.OUTCOMES, policy=policy, retain_inputs=retain_inputs, **run_kwargs)
    for i, item in enumerate(items):
        outcome, reason, ext = decider.decide(item["input"])
        run.decide(item["input"], outcome, reason, ts=f"2026-10-18T00:00:{i:02d}Z", label=item.get("label") if labelled else None, ext=ext)
    run.close(record_id=record_id, signing_key_id=keys["key_id"], private_key_pem=keys["pem"], issued_at="2026-10-18T01:00:00Z")
    return directory


def read_record(directory: Path) -> Dict[str, Any]:
    return json.loads((directory / RECORD_FILE).read_text())


def write_record(directory: Path, record: Dict[str, Any]) -> None:
    (directory / RECORD_FILE).write_text(json.dumps(record, indent=2, sort_keys=True))


def resign(directory: Path, pem: bytes, mutate) -> None:
    """Apply `mutate(record)` and re-sign with the given key: a dishonest producer."""
    record = read_record(directory)
    for k in ("payload_hash", "signature"):
        record.pop(k, None)
    mutate(record)
    write_record(directory, sign_record(record, pem))


def read_rows(directory: Path) -> List[Dict[str, Any]]:
    return [json.loads(l) for l in (directory / "decisions.jsonl").read_text().splitlines() if l.strip()]


def write_rows(directory: Path, rows: List[Dict[str, Any]]) -> None:
    (directory / "decisions.jsonl").write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def verify(directory: Path, keys, replay: Optional[str] = None) -> Report:
    return verify_directory(directory, keys["registry"], replay_module=replay)


def states(report: Report) -> Dict[str, str]:
    return {p["property"]: p["state"] for p in report.properties}

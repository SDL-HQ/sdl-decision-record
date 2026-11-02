"""Signatures, payload hashes, and what the registry decides."""

import json

from conftest import build_run, read_record, resign, states, verify, write_record
from dr.registry import load_registry, resolve
from dr.signing import SignatureCheckRaised, generate_private_key_pem, payload_hash, public_key_pem, sign_record, verify_signature


def test_payload_hash_recomputes_and_signature_verifies(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    r = read_record(d)
    assert r["payload_hash"] == payload_hash(r)
    assert verify_signature(r, public_key_pem(keys["pem"]))[0] is True


def test_editing_the_record_without_rehashing_fails_document(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    r = read_record(d)
    r["record_id"] = "renamed"
    write_record(d, r)
    s = states(verify(d, keys))
    assert s["document"] == "failed" and len(s) == 1


def test_editing_and_rehashing_without_the_key_fails_signature(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    r = read_record(d)
    r["record_id"] = "renamed"
    r["payload_hash"] = payload_hash(r)
    write_record(d, r)
    s = states(verify(d, keys))
    assert s["document"] == "established" and s["signature"] == "failed"


def test_a_key_not_in_the_registry_fails_trust_and_leaves_signature_unknown(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r.update(signing_key_id="nobody"))
    s = states(verify(d, keys))
    assert s["signing_trust"] == "failed" and s["signature"] == "unknown"


def test_a_retired_key_is_still_honoured(tmp_path, keys):
    reg = keys["registry_obj"]
    reg["keys"][0]["status"] = "retired"
    keys["registry"].write_text(json.dumps(reg))
    d = build_run(tmp_path / "run", keys)
    s = states(verify(d, keys))
    assert s["signing_trust"] == "established" and s["signature"] == "established"


def test_a_revoked_key_fails_unless_the_registry_names_the_record(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    reg = keys["registry_obj"]
    reg["keys"][0]["status"] = "revoked"
    reg["keys"][0]["trusted_after_revocation"] = []
    keys["registry"].write_text(json.dumps(reg))
    assert states(verify(d, keys))["signing_trust"] == "failed"
    reg["keys"][0]["trusted_after_revocation"] = [read_record(d)["payload_hash"]]
    keys["registry"].write_text(json.dumps(reg))
    s = states(verify(d, keys))
    assert s["signing_trust"] == "established" and s["signature"] == "established"


def test_a_revoked_key_cannot_be_laundered_by_a_signer_chosen_timestamp(tmp_path, keys):
    """There is no timestamp rule: a record from 'before' the revocation is still refused."""
    d = build_run(tmp_path / "run", keys)
    resign(d, keys["pem"], lambda r: r.update(issued_at="2001-01-01T00:00:00Z"))
    reg = keys["registry_obj"]
    reg["keys"][0]["status"] = "revoked"
    keys["registry"].write_text(json.dumps(reg))
    assert states(verify(d, keys))["signing_trust"] == "failed"


def test_a_malformed_registry_entry_is_unknown_not_failed(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    reg = keys["registry_obj"]
    reg["keys"][0]["public_key_pem"] = "not a key"
    keys["registry"].write_text(json.dumps(reg))
    s = states(verify(d, keys))
    assert s["signing_trust"] == "unknown" and s["signature"] == "unknown"
    assert verify(d, keys).verdict == 1


def test_an_unreadable_registry_is_unknown_not_failed(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    keys["registry"].write_text("{not json")
    s = states(verify(d, keys))
    assert s["signing_trust"] == "unknown"


def test_a_check_that_raises_is_reported_as_the_verifiers_problem(tmp_path, keys):
    d = build_run(tmp_path / "run", keys)
    r = read_record(d)
    r["signature"] = "@@not base64@@"
    r["payload_hash"] = payload_hash(r)
    write_record(d, r)
    s = states(verify(d, keys))
    assert s["signature"] == "unknown"


def test_resolve_states():
    pem = generate_private_key_pem()
    reg = {"registry_version": 1, "keys": [{"key_id": "a", "status": "active", "public_key_pem": public_key_pem(pem)}]}
    assert resolve(reg, "a", "sha256:x")[0] == "honoured"
    assert resolve(reg, "b", "sha256:x")[0] == "failed"
    assert resolve(reg, None, "sha256:x")[0] == "failed"
    reg["keys"][0]["status"] = "weird"
    assert resolve(reg, "a", "sha256:x")[0] == "unknown"


def test_sign_refuses_a_moving_payload():
    pem = generate_private_key_pem()
    signed = sign_record({"a": 1, "payload_hash": "stale", "signature": "stale"}, pem)
    assert signed["payload_hash"] == payload_hash(signed)

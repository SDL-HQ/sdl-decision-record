"""The key registry: which keys a reader honours, and what revocation means.

    {
      "registry_version": 1,
      "keys": [
        {"key_id": "...", "status": "active" | "retired" | "revoked",
         "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
         "trusted_after_revocation": ["sha256:<payload_hash>", ...]}
      ]
    }

A revoked key is assumed to be held by someone who can sign anything, including
a record carrying any timestamp or identifier they choose. So nothing inside a
record can place it before the revocation, and this format does not pretend
otherwise: a record signed by a revoked key fails signing trust unless the
registry itself names that record's payload_hash as trusted. Trust after
revocation is a registry decision about a specific document, never a property
the document asserts about itself.

`retired` means the key is no longer used to sign and is still honoured for
what it signed. `revoked` means it is not honoured for anything the registry
does not individually name.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from .canonical import loads as strict_loads

STATUSES = ("active", "retired", "revoked")


class RegistryUnreadable(Exception):
    """The registry could not be read or is malformed. A statement about the verifier's inputs."""


def load_registry(path: Path) -> Dict[str, Any]:
    try:
        obj = strict_loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:  # unreadable or not I-JSON; anything else is the verifier's and propagates
        raise RegistryUnreadable(f"registry {path}: {exc}") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("keys"), list):
        raise RegistryUnreadable(f"registry {path}: expected an object with a keys list")
    return obj


def find_key(registry: Dict[str, Any], key_id: str) -> Optional[Dict[str, Any]]:
    for entry in registry["keys"]:
        if isinstance(entry, dict) and entry.get("key_id") == key_id:
            return entry
    return None


def resolve(registry: Dict[str, Any], key_id: Any, record_payload_hash: Any) -> Tuple[str, str, Optional[str]]:
    """Decide whether this registry honours key_id for this record.

    Returns (state, detail, public_key_pem). state is one of:
      "honoured"   verify with the returned key
      "failed"     the registry does not honour this key for this record
      "unknown"    the registry entry is malformed, so nothing can be decided
    """
    if not isinstance(key_id, str) or not key_id:
        return "failed", "the record names no signing_key_id", None
    entry = find_key(registry, key_id)
    if entry is None:
        return "failed", f"signing_key_id {key_id!r} is not in the registry", None
    status = entry.get("status")
    pem = entry.get("public_key_pem")
    if status not in STATUSES or not isinstance(pem, str) or "BEGIN PUBLIC KEY" not in pem:
        return "unknown", f"registry entry {key_id!r} is malformed (status {status!r}); nothing about this signature can be decided", None
    if status == "revoked":
        trusted = entry.get("trusted_after_revocation") or []
        if isinstance(trusted, list) and record_payload_hash in trusted:
            return "honoured", f"key {key_id!r} is revoked and the registry individually trusts this record's payload_hash", pem
        return "failed", f"key {key_id!r} is revoked and the registry does not individually trust this record", None
    return "honoured", f"key {key_id!r} is {status} in the registry", pem

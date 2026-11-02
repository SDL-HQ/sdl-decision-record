"""Signing a record, in one place.

    payload       canonical bytes of the record without payload_hash and signature
    payload_hash  sha256 digest of the payload
    signature     Ed25519 over the payload, base64

Ed25519 rather than RSA: no padding choices, no parameters, small keys, and the
cryptography package exposes it with nothing to configure. The payload is the
canonical form (sorted keys), so a verifier rebuilds the same bytes from any
serialisation of the same object.
"""

from __future__ import annotations

import base64
from typing import Any, Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes, digest_bytes

UNSIGNED_FIELDS = ("payload_hash", "signature")


def payload_bytes(record: Dict[str, Any]) -> bytes:
    return canonical_bytes({k: v for k, v in record.items() if k not in UNSIGNED_FIELDS})


def payload_hash(record: Dict[str, Any]) -> str:
    return digest_bytes(payload_bytes(record))


def generate_private_key_pem() -> bytes:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def public_key_pem(private_key_pem: bytes) -> str:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def sign_record(record: Dict[str, Any], private_key_pem: bytes) -> Dict[str, Any]:
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("the signing key must be Ed25519")
    body = {k: v for k, v in record.items() if k not in UNSIGNED_FIELDS}
    payload = canonical_bytes(body)
    signed = dict(body)
    signed["payload_hash"] = digest_bytes(payload)
    signed["signature"] = base64.b64encode(key.sign(payload)).decode("ascii")
    if payload_bytes(signed) != payload:
        raise RuntimeError("refusing to sign: the payload moved while the signature was attached")
    return signed


class SignatureCheckRaised(Exception):
    """The check could not be performed. A statement about the verifier, not the record."""


def verify_signature(record: Dict[str, Any], public_pem: str) -> Tuple[bool, str]:
    """(verified, detail). Raises SignatureCheckRaised if the check itself breaks."""
    try:
        key = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        if not isinstance(key, Ed25519PublicKey):
            raise SignatureCheckRaised("the registry key is not Ed25519")
        sig = base64.b64decode(str(record.get("signature", "")), validate=True)
    except SignatureCheckRaised:
        raise
    except Exception as exc:  # malformed key material or base64: our side or the file's shape
        raise SignatureCheckRaised(str(exc)) from exc
    try:
        key.verify(sig, payload_bytes(record))
    except InvalidSignature:
        return False, "the signature does not verify over the payload"
    except Exception as exc:
        raise SignatureCheckRaised(str(exc)) from exc
    return True, "the signature verifies over the payload"

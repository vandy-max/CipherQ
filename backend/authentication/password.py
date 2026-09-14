"""
Password hashing — PBKDF2-HMAC-SHA256.

Same algorithm, iteration count, and hex-salt format as the reference
project's `hash_password`; reimplemented here as pure functions with
a constant-time comparison for verification (the reference compared
hashes with `==`, which is a minor timing-attack surface worth closing
even in a prototype).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

_ITERATIONS = 100_000
_ALGORITHM = "sha256"


def generate_salt() -> str:
    return secrets.token_hex(16)


def hash_password(password: str, salt: str) -> str:
    if not password:
        raise ValueError("password must not be empty")
    if not salt:
        raise ValueError("salt must not be empty")
    return hashlib.pbkdf2_hmac(
        _ALGORITHM, password.encode("utf-8"), bytes.fromhex(salt), _ITERATIONS
    ).hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, expected_hash)

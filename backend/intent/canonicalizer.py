"""
Deterministic canonicalization of a Cryptographic Intent Descriptor (CID).

The same logical intent must always produce the same hash regardless of
field construction order, absent-vs-null optional fields, datetime
sub-second precision, or Unicode normalization form of string values.
This module is the single source of truth for that contract — every
other module (crypto, policy, audit) that needs "the intent hash" must
go through `compute_intent_hash`, never hash a CID ad hoc.
"""
from __future__ import annotations

import hashlib
import json
import unicodedata
from datetime import datetime, timezone
from typing import Any

from .schema import CID

_HASH_ALGORITHM = "sha256"


def _iso_seconds_utc(value: datetime) -> str:
    """Render a datetime as UTC ISO-8601 truncated to whole seconds."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def _normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _normalize(val) for key, val in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, datetime):
        return _iso_seconds_utc(value)
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    return value


def canonicalize_cid(cid: CID) -> dict:
    """Return a plain dict representation with normalized values.

    None-valued optional fields are dropped entirely so that an absent
    field and a field explicitly set to null canonicalize identically.
    """
    raw = cid.model_dump(exclude_none=True, mode="python")
    normalized = _normalize(raw)
    if not isinstance(normalized, dict):  # pragma: no cover - defensive
        raise TypeError("CID normalization did not produce a dict")
    return normalized


def canonical_json_bytes(cid: CID) -> bytes:
    """Serialize a CID to canonical JSON bytes: sorted keys, no whitespace."""
    normalized = canonicalize_cid(cid)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def compute_intent_hash(cid: CID) -> str:
    """Return the hex-encoded SHA-256 Intent Hash for a CID."""
    digest = hashlib.new(_HASH_ALGORITHM, canonical_json_bytes(cid))
    return digest.hexdigest()

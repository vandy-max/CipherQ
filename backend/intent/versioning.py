"""
Immutable intent versioning.

An Intent is never overwritten. Every modification produces a new,
append-only IntentVersion (v1, v2, v3, ...). This module contains the
pure domain logic for constructing a version; persistence lives in the
database layer / a future intent service, which will use this as its
single source of truth for "what does a version look like".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .canonicalizer import compute_intent_hash
from .schema import CID


@dataclass(frozen=True)
class IntentVersion:
    version_number: int
    cid: CID
    canonical_hash: str
    author: str
    reason: str
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


def create_version(
    cid: CID,
    version_number: int,
    author: str,
    reason: str,
) -> IntentVersion:
    """Build the next immutable version for an intent.

    `version_number` is the caller's responsibility (typically
    `previous_version_number + 1`, starting at 1) so this module stays
    free of any database/state dependency.
    """
    if version_number < 1:
        raise ValueError("version_number must start at 1")
    if not author:
        raise ValueError("author is required for an intent version")
    if not reason:
        raise ValueError("reason is required for an intent version")

    return IntentVersion(
        version_number=version_number,
        cid=cid,
        canonical_hash=compute_intent_hash(cid),
        author=author,
        reason=reason,
    )

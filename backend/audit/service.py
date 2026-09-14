from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol, Sequence

from .hash_chain import GENESIS_HASH, AuditEntry, ChainVerificationResult, build_entry, verify_chain


class AuditLogRepository(Protocol):
    """Storage abstraction so AuditLogService is unit-testable without
    a database. A MongoDB-backed implementation is wired in at the
    api/ stage; `InMemoryAuditLogRepository` below is for tests only.
    """

    def get_last_hash(self) -> str: ...
    def append(self, entry: AuditEntry) -> None: ...
    def all_entries(self) -> Sequence[AuditEntry]: ...


class InMemoryAuditLogRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def get_last_hash(self) -> str:
        return self._entries[-1].current_log_hash if self._entries else GENESIS_HASH

    def append(self, entry: AuditEntry) -> None:
        self._entries.append(entry)

    def all_entries(self) -> Sequence[AuditEntry]:
        return tuple(self._entries)


class AuditLogService:
    """Constructor-injected repository — swap in a DB-backed one in
    the API layer without touching this class."""

    def __init__(self, repository: AuditLogRepository) -> None:
        self._repository = repository

    def record(
        self,
        action: str,
        result: str,
        user_id: int | None = None,
        intent_hash: str | None = None,
        timestamp: datetime | None = None,
        session_id: str | None = None,
        device_id: str | None = None,
        resource: str | None = None,
        operation: str | None = None,
        risk: str | None = None,
        reason: str | None = None,
    ) -> AuditEntry:
        # Audit timestamps represent the actual moment this audit event is
        # recorded, not a timestamp borrowed from another workflow object.
        # Keep the optional `timestamp` argument for backward compatibility
        # with existing callers/tests, but deliberately do not use it.
        #
        # Normalize to millisecond precision *before* hashing. MongoDB's
        # BSON datetime type only stores millisecond precision, so a
        # microsecond-precision Python datetime silently loses its bottom
        # 3 digits on the round trip through the database. Truncating
        # before hashing keeps the hashed and persisted values identical.
        ts = datetime.now(timezone.utc)
        ts = ts.replace(microsecond=(ts.microsecond // 1000) * 1000)
        entry = build_entry(
            prev_log_hash=self._repository.get_last_hash(),
            timestamp=ts,
            user_id=user_id,
            action=action,
            intent_hash=intent_hash,
            result=result,
            session_id=session_id,
            device_id=device_id,
            resource=resource,
            operation=operation,
            risk=risk,
            reason=reason,
        )
        self._repository.append(entry)
        return entry

    def verify_integrity(self) -> ChainVerificationResult:
        # Verification is strictly read-only. Do not append a tamper alert
        # into the same chain being verified; doing so would make a broken
        # chain permanently self-contaminating.
        return verify_chain(self._repository.all_entries())

    def list_entries(self) -> Sequence[AuditEntry]:
        return self._repository.all_entries()
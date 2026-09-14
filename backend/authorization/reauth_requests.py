"""
Reauthorization requests — the user-facing escape hatch for the cases
`POST /sessions/{id}/reauthenticate` deliberately refuses to fix by
itself for a non-admin account: a REVOKED DEVICE, and (per updated
policy) a REVOKED SESSION.

Continuous monitoring can revoke either a session or, for
repeated/severe failures, the DEVICE itself (`monitoring/service.py`'s
`invalidate_after` escalation). Both are intentionally boundaries a
face check alone cannot cross on its own: `reauthenticate_session`
403s for a revoked device with "an administrator must restore the
device", and — now — for a revoked session too, with "an administrator
must approve an access request", rather than silently clearing either,
because a face check alone shouldn't be able to undo a security
decision continuous monitoring (or an admin) made. The one exception
is an ADMIN account acting on their own session/device: there is no
higher authority for an admin to ask, so `reauthenticate_session`
self-services that one case (see `admin_self_service_restore` there).

Without this module, a non-admin user whose device or session gets
revoked has NO in-app path forward — only a raw device/session
repository unrevoke, which is exactly the same manual DB/API action
support previously had to walk them through by hand. This module gives
that flow a proper, auditable shape: the blocked user submits one
message explaining the situation, an admin sees it with full context
(who, which device/session, when, why) in one place, and
approving/rejecting it is a single click that immediately reflects
back to the user's live monitoring state.

Same `_id = get_next_id(...)` integer-id convention as every other
collection (see `qira/repository.py`'s `SecurityIncident`, which this
mirrors closely on purpose).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from pymongo.collection import ReturnDocument
from pymongo.database import Database

from database.models import REAUTH_REQUESTS_COLLECTION
from database.session import get_next_id

PENDING = "pending"
APPROVED = "approved"
REJECTED = "rejected"
CONSUMED = "consumed"


@dataclass(frozen=True)
class ReauthRequest:
    request_id: int
    user_id: int
    username: str
    device_id: str
    session_id: str
    message: str
    status: str
    created_at: datetime
    resolved_by: int | None = None
    resolved_by_username: str | None = None
    resolved_at: datetime | None = None
    resolution_note: str | None = None
    consumed_at: datetime | None = None

    def as_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "user_id": self.user_id,
            "username": self.username,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "message": self.message,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "resolved_by": self.resolved_by,
            "resolved_by_username": self.resolved_by_username,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_note": self.resolution_note,
            "consumed_at": self.consumed_at.isoformat() if self.consumed_at else None,
        }


def _aware(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _from_doc(doc: dict) -> ReauthRequest:
    return ReauthRequest(
        request_id=doc["_id"],
        user_id=doc["user_id"],
        username=doc["username"],
        device_id=doc["device_id"],
        session_id=doc["session_id"],
        message=doc["message"],
        status=doc["status"],
        created_at=_aware(doc["created_at"]),
        resolved_by=doc.get("resolved_by"),
        resolved_by_username=doc.get("resolved_by_username"),
        resolved_at=_aware(doc.get("resolved_at")),
        resolution_note=doc.get("resolution_note"),
        consumed_at=_aware(doc.get("consumed_at")),
    )


class ReauthRequestRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(
        self,
        *,
        user_id: int,
        username: str,
        device_id: str,
        session_id: str,
        message: str,
        now: datetime | None = None,
    ) -> ReauthRequest:
        now = now or datetime.now(timezone.utc)
        request_id = get_next_id(REAUTH_REQUESTS_COLLECTION)
        doc = {
            "_id": request_id,
            "user_id": user_id,
            "username": username,
            "device_id": device_id,
            "session_id": session_id,
            "message": message,
            "status": PENDING,
            "created_at": now,
            "resolved_by": None,
            "resolved_by_username": None,
            "resolved_at": None,
            "resolution_note": None,
        }
        self._db[REAUTH_REQUESTS_COLLECTION].insert_one(doc)
        return _from_doc(doc)

    def get(self, request_id: int) -> ReauthRequest | None:
        doc = self._db[REAUTH_REQUESTS_COLLECTION].find_one({"_id": request_id})
        return _from_doc(doc) if doc else None

    def list_all(self, *, status: str | None = None) -> list[ReauthRequest]:
        query: dict = {}
        if status is not None:
            query["status"] = status
        docs = self._db[REAUTH_REQUESTS_COLLECTION].find(query).sort("created_at", -1)
        return [_from_doc(d) for d in docs]


    def get_approved_for(self, user_id: int, device_id: str, session_id: str) -> ReauthRequest | None:
        """Return the current approved request for this exact recovery target.

        Approval is scoped to the user + device + session.  This prevents an
        old approval for the same browser/device from being mistaken for an
        approval of a newer session.
        """
        doc = self._db[REAUTH_REQUESTS_COLLECTION].find_one(
            {
                "user_id": user_id,
                "device_id": device_id,
                "session_id": session_id,
                "status": APPROVED,
            },
            sort=[("resolved_at", -1), ("_id", -1)],
        )
        return _from_doc(doc) if doc else None

    def consume_approved(
        self,
        request_id: int,
        *,
        user_id: int,
        device_id: str,
        session_id: str,
        now: datetime | None = None,
    ) -> ReauthRequest | None:
        """Atomically consume one approved recovery grant after face verification."""
        now = now or datetime.now(timezone.utc)
        doc = self._db[REAUTH_REQUESTS_COLLECTION].find_one_and_update(
            {
                "_id": request_id,
                "user_id": user_id,
                "device_id": device_id,
                "session_id": session_id,
                "status": APPROVED,
            },
            {"$set": {"status": CONSUMED, "consumed_at": now}},
            return_document=ReturnDocument.AFTER,
        )
        return _from_doc(doc) if doc else None

    def list_for_user(self, user_id: int) -> list[ReauthRequest]:
        docs = (
            self._db[REAUTH_REQUESTS_COLLECTION]
            .find({"user_id": user_id})
            .sort("created_at", -1)
        )
        return [_from_doc(d) for d in docs]

    def has_pending_for(self, user_id: int, device_id: str, session_id: str) -> bool:
        return (
            self._db[REAUTH_REQUESTS_COLLECTION].find_one(
                {
                    "user_id": user_id,
                    "device_id": device_id,
                    "session_id": session_id,
                    "status": PENDING,
                }
            )
            is not None
        )

    def resolve(
        self,
        request_id: int,
        *,
        new_status: str,
        resolved_by: int,
        resolved_by_username: str,
        note: str | None,
        now: datetime | None = None,
    ) -> ReauthRequest | None:
        assert new_status in (APPROVED, REJECTED)
        now = now or datetime.now(timezone.utc)
        doc = self._db[REAUTH_REQUESTS_COLLECTION].find_one_and_update(
            {"_id": request_id, "status": PENDING},
            {
                "$set": {
                    "status": new_status,
                    "resolved_by": resolved_by,
                    "resolved_by_username": resolved_by_username,
                    "resolved_at": now,
                    "resolution_note": note,
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return _from_doc(doc) if doc else None

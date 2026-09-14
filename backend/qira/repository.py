"""
Persistence for Qira security incidents (Part 13/14/21 of the brief).

Kept as its own small repository — separate from `api/repositories.py`
— so the Qira package stays a self-contained, additive layer on top of
the existing persistence code rather than growing the shared
repositories module. Same `_id = get_next_id(...)` integer-id
convention as every other collection (see `database/models.py`).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from pymongo.collection import ReturnDocument
from pymongo.database import Database

from database.models import SECURITY_INCIDENTS_COLLECTION
from database.session import get_next_id


@dataclass(frozen=True)
class SecurityIncident:
    incident_id: int
    user_id: int
    device_id: str
    session_id: str
    monitoring_session_id: str
    severity: str
    security_state: str
    reason: str
    signals: tuple[str, ...]
    action_taken: str
    qira_assessment: dict | None
    detected_at: datetime
    resolved: bool = False
    resolved_by: int | None = None
    resolved_at: datetime | None = None
    resolution_note: str | None = None

    def as_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "monitoring_session_id": self.monitoring_session_id,
            "severity": self.severity,
            "security_state": self.security_state,
            "reason": self.reason,
            "signals": list(self.signals),
            "action_taken": self.action_taken,
            "qira_assessment": self.qira_assessment,
            "detected_at": self.detected_at.isoformat(),
            "resolved": self.resolved,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_note": self.resolution_note,
        }


def _from_doc(doc: dict) -> SecurityIncident:
    detected_at = doc["detected_at"]
    if detected_at.tzinfo is None:
        detected_at = detected_at.replace(tzinfo=timezone.utc)
    resolved_at = doc.get("resolved_at")
    if resolved_at is not None and resolved_at.tzinfo is None:
        resolved_at = resolved_at.replace(tzinfo=timezone.utc)
    return SecurityIncident(
        incident_id=doc["_id"],
        user_id=doc["user_id"],
        device_id=doc["device_id"],
        session_id=doc["session_id"],
        monitoring_session_id=doc["monitoring_session_id"],
        severity=doc["severity"],
        security_state=doc["security_state"],
        reason=doc["reason"],
        signals=tuple(doc.get("signals", [])),
        action_taken=doc["action_taken"],
        qira_assessment=doc.get("qira_assessment"),
        detected_at=detected_at,
        resolved=doc.get("resolved", False),
        resolved_by=doc.get("resolved_by"),
        resolved_at=resolved_at,
        resolution_note=doc.get("resolution_note"),
    )


class SecurityIncidentRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(
        self,
        *,
        user_id: int,
        device_id: str,
        session_id: str,
        monitoring_session_id: str,
        severity: str,
        security_state: str,
        reason: str,
        signals: tuple[str, ...],
        action_taken: str,
        qira_assessment: dict | None,
        now: datetime | None = None,
    ) -> SecurityIncident:
        now = now or datetime.now(timezone.utc)
        incident_id = get_next_id(SECURITY_INCIDENTS_COLLECTION)
        doc = {
            "_id": incident_id,
            "user_id": user_id,
            "device_id": device_id,
            "session_id": session_id,
            "monitoring_session_id": monitoring_session_id,
            "severity": severity,
            "security_state": security_state,
            "reason": reason,
            "signals": list(signals),
            "action_taken": action_taken,
            "qira_assessment": qira_assessment,
            "detected_at": now,
            "resolved": False,
            "resolved_by": None,
            "resolved_at": None,
            "resolution_note": None,
        }
        self._db[SECURITY_INCIDENTS_COLLECTION].insert_one(doc)
        return _from_doc(doc)

    def get(self, incident_id: int) -> SecurityIncident | None:
        doc = self._db[SECURITY_INCIDENTS_COLLECTION].find_one({"_id": incident_id})
        return _from_doc(doc) if doc else None

    def list_all(self, *, resolved: bool | None = None) -> list[SecurityIncident]:
        query: dict = {}
        if resolved is not None:
            query["resolved"] = resolved
        docs = self._db[SECURITY_INCIDENTS_COLLECTION].find(query).sort("detected_at", -1)
        return [_from_doc(d) for d in docs]

    def resolve(
        self, incident_id: int, *, resolved_by: int, note: str, now: datetime | None = None
    ) -> SecurityIncident | None:
        now = now or datetime.now(timezone.utc)
        doc = self._db[SECURITY_INCIDENTS_COLLECTION].find_one_and_update(
            {"_id": incident_id},
            {
                "$set": {
                    "resolved": True,
                    "resolved_by": resolved_by,
                    "resolved_at": now,
                    "resolution_note": note,
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return _from_doc(doc) if doc else None

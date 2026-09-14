"""
MongoDB-backed (PyMongo) repositories.

Each class here satisfies a Protocol defined in a domain module
(`authentication.service.UserRepository`,
`authentication.face_auth.FaceDescriptorRepository`,
`audit.service.AuditLogRepository`) so those services stay unaware of
MongoDB entirely. `IntentRepository` and `EncryptionRecordRepository`
are API-layer-only concerns (the domain modules don't define
persistence interfaces for them) since versioning/lifecycle DB writes
naturally live alongside the document representations.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Sequence

from pymongo.collection import ReturnDocument
from pymongo.database import Database

from audit.hash_chain import GENESIS_HASH, AuditEntry
from authentication.service import UserRecord
from authorization.devices import DeviceStatus
from authorization.sessions import SessionRevokedError, SessionState
from crypto.aes_gcm import EncryptionEnvelope
from database.models import AUDIT_LOGS_COLLECTION
from database.models import AuditLog as AuditLogModel
from database.models import AUTH_SESSIONS_COLLECTION
from database.models import DEVICES_COLLECTION
from database.models import ENCRYPTION_RECORDS_COLLECTION
from database.models import EncryptionRecord as EncryptionRecordModel
from database.models import INTENT_VERSIONS_COLLECTION
from database.models import INTENTS_COLLECTION
from database.models import Intent as IntentModel
from database.models import IntentVersion as IntentVersionModel
from database.models import MONITORING_EVENTS_COLLECTION
from database.models import MONITORING_SESSIONS_COLLECTION
from database.models import POLICIES_COLLECTION
from database.models import Policy as PolicyModel
from database.models import TRUSTED_LOCATIONS_COLLECTION
from database.models import USERS_COLLECTION
from database.models import User as UserModel
from database.session import get_next_id
from intent.canonicalizer import canonical_json_bytes, compute_intent_hash
from intent.lifecycle import IntentState, validate_transition
from intent.schema import CID
from monitoring.service import MonitoringEvent, MonitoringSessionRecord
from monitoring.state import IdentityCheckState, MonitoringSnapshot, MonitoringStatus, MonitoringThresholds, SecurityPostureState
from policy.risk import RiskLevel
from policy.geofence import TrustedLocation


# ---------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------

def _to_user_record(row: UserModel) -> UserRecord:
    return UserRecord(
        id=row.id,
        username=row.username,
        email=row.email,
        password_hash=row.password_hash,
        salt=row.salt,
        role=row.role,
    )


class MongoUserRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_by_username(self, username: str) -> UserRecord | None:
        doc = self._db[USERS_COLLECTION].find_one({"username": username})
        return _to_user_record(UserModel.from_document(doc)) if doc is not None else None

    def get_by_id(self, user_id: int) -> UserRecord | None:
        doc = self._db[USERS_COLLECTION].find_one({"_id": user_id})
        return _to_user_record(UserModel.from_document(doc)) if doc is not None else None

    def list_all(self) -> list[UserRecord]:
        """Admin-only user listing (see api/routers/users.py). Returns
        every registered user, ordered by id, for the User & Role
        Management admin section."""
        return [
            _to_user_record(UserModel.from_document(doc))
            for doc in self._db[USERS_COLLECTION].find().sort("_id", 1)
        ]

    def update_role(self, user_id: int, role: str) -> UserRecord | None:
        doc = self._db[USERS_COLLECTION].find_one_and_update(
            {"_id": user_id}, {"$set": {"role": role}}, return_document=ReturnDocument.AFTER
        )
        return _to_user_record(UserModel.from_document(doc)) if doc is not None else None

    def create(
        self, username: str, email: str, password_hash: str, salt: str, role: str
    ) -> UserRecord:
        doc = {
            "_id": get_next_id(USERS_COLLECTION),
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "salt": salt,
            "role": role,
            "face_descriptor": None,
            "created_at": datetime.now(timezone.utc),
        }
        self._db[USERS_COLLECTION].insert_one(doc)
        # Read the document back through the same encrypted repository
        # boundary used by login. This makes registration fail loudly if
        # the write/read database path is inconsistent instead of issuing
        # a token for a user that cannot subsequently be authenticated.
        stored = self._db[USERS_COLLECTION].find_one({"_id": doc["_id"]})
        if stored is None:
            raise RuntimeError("user registration was written but could not be read back from the configured database")
        return _to_user_record(UserModel.from_document(stored))


# ---------------------------------------------------------------------
# Face descriptors (identity verification only)
# ---------------------------------------------------------------------

class MongoFaceDescriptorRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_enrolled_descriptor(self, user_id: int) -> Sequence[float] | None:
        doc = self._db[USERS_COLLECTION].find_one(
            {"_id": user_id}, {"face_descriptor": 1}
        )
        if doc is None or not doc.get("face_descriptor"):
            return None
        return doc["face_descriptor"]

    def save_enrolled_descriptor(self, user_id: int, descriptor: Sequence[float]) -> None:
        result = self._db[USERS_COLLECTION].update_one(
            {"_id": user_id}, {"$set": {"face_descriptor": list(descriptor)}}
        )
        if result.matched_count == 0:
            raise ValueError(f"no user with id {user_id}")


# ---------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------

class MongoAuditLogRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_last_hash(self) -> str:
        # Older audit documents may predate the hash-chain fields. Never let
        # a legacy document turn an ordinary login failure into HTTP 500.
        # Continue from the newest document that actually belongs to the
        # current hash chain; integrity verification remains responsible for
        # reporting malformed historical entries.
        cursor = self._db[AUDIT_LOGS_COLLECTION].find(
            {"current_log_hash": {"$exists": True}}
        ).sort("_id", -1)
        for doc in cursor:
            current_hash = doc.get("current_log_hash")
            if current_hash:
                return current_hash
        return GENESIS_HASH

    def append(self, entry: AuditEntry) -> None:
        doc = {
            "_id": get_next_id(AUDIT_LOGS_COLLECTION),
            "timestamp": entry.timestamp,
            "user_id": entry.user_id,
            "action": entry.action,
            "intent_hash": entry.intent_hash,
            "result": entry.result,
            "prev_log_hash": entry.prev_log_hash,
            "current_log_hash": entry.current_log_hash,
            "session_id": entry.session_id,
            "device_id": entry.device_id,
            "resource": entry.resource,
            "operation": entry.operation,
            "risk": entry.risk,
            "reason": entry.reason,
        }
        self._db[AUDIT_LOGS_COLLECTION].insert_one(doc)

    def all_entries(self) -> Sequence[AuditEntry]:
        cursor = self._db[AUDIT_LOGS_COLLECTION].find().sort("_id", 1)
        return [
            AuditEntry(
                timestamp=doc["timestamp"],
                user_id=doc["user_id"],
                action=doc["action"],
                intent_hash=doc["intent_hash"],
                result=doc["result"],
                prev_log_hash=doc["prev_log_hash"],
                current_log_hash=doc["current_log_hash"],
                # .get(...) — Phase 1-3 documents predate these fields;
                # they read back as None, which recomputes identically
                # to how they were originally hashed (empty-string).
                session_id=doc.get("session_id"),
                device_id=doc.get("device_id"),
                resource=doc.get("resource"),
                operation=doc.get("operation"),
                risk=doc.get("risk"),
                reason=doc.get("reason"),
            )
            for doc in cursor
        ]


# ---------------------------------------------------------------------
# Intents (append-only versioning + lifecycle)
# ---------------------------------------------------------------------

class IntentRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(self, cid: CID, author: str, reason: str, created_by: int) -> IntentModel:
        canonical_hash = compute_intent_hash(cid)
        now = datetime.now(timezone.utc)

        intent_id = get_next_id(INTENTS_COLLECTION)
        version_id = get_next_id(INTENT_VERSIONS_COLLECTION)

        version_doc = {
            "_id": version_id,
            "intent_id": intent_id,
            "version_number": 1,
            "cid_json": canonical_json_bytes(cid).decode("utf-8"),
            "canonical_hash": canonical_hash,
            "author": author,
            "reason": reason,
            "created_at": now,
        }
        self._db[INTENT_VERSIONS_COLLECTION].insert_one(version_doc)

        intent_doc = {
            "_id": intent_id,
            "current_version_id": version_id,
            "canonical_hash": canonical_hash,
            "lifecycle_state": IntentState.DRAFT.value,
            "created_by": created_by,
            "created_at": now,
        }
        self._db[INTENTS_COLLECTION].insert_one(intent_doc)

        return IntentModel.from_document(intent_doc)

    def get_by_id(self, intent_id: int) -> IntentModel | None:
        doc = self._db[INTENTS_COLLECTION].find_one({"_id": intent_id})
        return IntentModel.from_document(doc) if doc is not None else None

    def list_all(self, *, created_by: int | None = None, lifecycle_state: IntentState | None = None) -> list[IntentModel]:
        """Backs `GET /api/intent` (see api/routers/intent.py). Role
        scoping happens at the router: a USER_LEVEL_1 caller passes its
        own `created_by`, an ADMIN/USER_LEVEL_2 caller passes `None`
        to see every intent (needed to actually find something to
        review/approve)."""
        query: dict = {}
        if created_by is not None:
            query["created_by"] = created_by
        if lifecycle_state is not None:
            query["lifecycle_state"] = lifecycle_state.value
        cursor = self._db[INTENTS_COLLECTION].find(query).sort([("created_at", -1), ("_id", -1)])
        return [IntentModel.from_document(doc) for doc in cursor]

    def get_by_hash(self, canonical_hash: str) -> IntentModel | None:
        doc = self._db[INTENTS_COLLECTION].find_one({"canonical_hash": canonical_hash})
        return IntentModel.from_document(doc) if doc is not None else None

    def current_version_number(self, intent_id: int) -> int:
        doc = self._db[INTENT_VERSIONS_COLLECTION].find_one(
            {"intent_id": intent_id}, sort=[("version_number", -1)]
        )
        return doc["version_number"] if doc is not None else 0

    def get_current_cid(self, intent_row: IntentModel) -> CID:
        """Reconstruct the CID this intent was created/last versioned
        with, from its `current_version_id`'s stored canonical JSON.

        Used by the approval workflow (`/api/intent/{id}/transition`)
        so that DRAFT -> APPROVED can be re-validated (policy, risk,
        device, session, approval-eligibility) against the intent's
        OWN recorded CID, without requiring the caller to resubmit it
        and without trusting a client-supplied CID for an approval
        decision.
        """
        version_doc = self._db[INTENT_VERSIONS_COLLECTION].find_one(
            {"_id": intent_row.current_version_id}
        )
        if version_doc is None:
            raise ValueError(f"no intent version found for intent {intent_row.id}")
        return CID(**json.loads(version_doc["cid_json"]))

    def transition(self, intent_row: IntentModel, target: IntentState) -> IntentModel:
        """Raises intent.lifecycle.InvalidTransitionError if not allowed."""
        validate_transition(intent_row.lifecycle_state, target)
        self._db[INTENTS_COLLECTION].update_one(
            {"_id": intent_row.id}, {"$set": {"lifecycle_state": target.value}}
        )
        intent_row.lifecycle_state = target
        return intent_row


# ---------------------------------------------------------------------
# Encryption records (ciphertext/nonce/tag only — never a key)
# ---------------------------------------------------------------------

class EncryptionRecordRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def save(
        self,
        envelope: EncryptionEnvelope,
        intent_version_id: int,
        created_by: int,
    ) -> EncryptionRecordModel:
        doc = {
            "_id": get_next_id(ENCRYPTION_RECORDS_COLLECTION),
            "ciphertext": envelope.ciphertext,
            "nonce": envelope.nonce,
            "auth_tag": envelope.auth_tag,
            "intent_hash": envelope.intent_hash,
            "intent_version_id": intent_version_id,
            "created_by": created_by,
            "created_at": envelope.created_at,
            "authorization_state_hash": envelope.authorization_state_hash,
        }
        self._db[ENCRYPTION_RECORDS_COLLECTION].insert_one(doc)
        return EncryptionRecordModel.from_document(doc)

    def get(self, record_id: int) -> EncryptionRecordModel | None:
        doc = self._db[ENCRYPTION_RECORDS_COLLECTION].find_one({"_id": record_id})
        return EncryptionRecordModel.from_document(doc) if doc is not None else None


# ---------------------------------------------------------------------
# Policies (config rows for the policy engine's allow-lists)
# ---------------------------------------------------------------------

class PolicyRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def list_all(self) -> Sequence[PolicyModel]:
        cursor = self._db[POLICIES_COLLECTION].find()
        return [PolicyModel.from_document(doc) for doc in cursor]

    def get(self, policy_id: int) -> PolicyModel | None:
        doc = self._db[POLICIES_COLLECTION].find_one({"_id": policy_id})
        return PolicyModel.from_document(doc) if doc is not None else None

    def create(self, name: str, rule_type: str, config: dict, active: bool) -> PolicyModel:
        doc = {
            "_id": get_next_id(POLICIES_COLLECTION),
            "name": name,
            "rule_type": rule_type,
            "config_json": config,
            "active": active,
            "created_at": datetime.now(timezone.utc),
        }
        self._db[POLICIES_COLLECTION].insert_one(doc)
        return PolicyModel.from_document(doc)

    def update(
        self, policy_id: int, name: str, rule_type: str, config: dict, active: bool
    ) -> PolicyModel | None:
        doc = self._db[POLICIES_COLLECTION].find_one_and_update(
            {"_id": policy_id},
            {
                "$set": {
                    "name": name,
                    "rule_type": rule_type,
                    "config_json": config,
                    "active": active,
                }
            },
            return_document=ReturnDocument.AFTER,
        )
        return PolicyModel.from_document(doc) if doc is not None else None

    def delete(self, policy_id: int) -> bool:
        result = self._db[POLICIES_COLLECTION].delete_one({"_id": policy_id})
        return result.deleted_count > 0


# ---------------------------------------------------------------------
# Devices / sessions (continuous-authorization state — see
# `authorization/`). Satisfy the `authorization.devices.DeviceRepository`
# and `authorization.sessions.SessionRepository` Protocols.
# ---------------------------------------------------------------------

class MongoDeviceRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_status(self, device_id: str) -> DeviceStatus:
        doc = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$setOnInsert": {"revoked": False}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return DeviceStatus(device_id=device_id, revoked=doc.get("revoked", False))

    def revoke(self, device_id: str) -> DeviceStatus:
        doc = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$set": {"revoked": True}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return DeviceStatus(device_id=device_id, revoked=doc.get("revoked", False))

    def unrevoke(self, device_id: str) -> DeviceStatus:
        doc = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$set": {"revoked": False}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return DeviceStatus(device_id=device_id, revoked=doc.get("revoked", False))

    # -- Ownership (API-layer concern only, additive to the plain
    # DeviceStatus domain model used by authorization/monitoring
    # internals, which intentionally know nothing about "who owns
    # this device" — only whether it's revoked). --

    def get_owner(self, device_id: str) -> int | None:
        doc = self._db[DEVICES_COLLECTION].find_one({"_id": device_id})
        return doc.get("user_id") if doc is not None else None

    def claim_owner(self, device_id: str, user_id: int) -> int:
        """The first user to ever establish a session with this
        device becomes its recorded owner. Idempotent and atomic: if
        the device already has an owner (including this same caller),
        the existing owner is returned unchanged — this never silently
        transfers ownership of an already-owned device."""
        self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id},
            {"$setOnInsert": {"revoked": False}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        claimed = self._db[DEVICES_COLLECTION].find_one_and_update(
            {"_id": device_id, "user_id": {"$exists": False}},
            {"$set": {"user_id": user_id}},
            return_document=ReturnDocument.AFTER,
        )
        if claimed is not None:
            return claimed["user_id"]
        existing = self._db[DEVICES_COLLECTION].find_one({"_id": device_id})
        return existing["user_id"]


def _to_session_state(doc: dict) -> SessionState:
    # MongoDB/BSON round-trips datetimes as timezone-naive UTC — every
    # datetime written here is UTC-aware (see get_or_create/refresh
    # below), so a naive value read back is always UTC and safe to
    # reattach tzinfo to. Without this, comparing against an
    # aware `datetime.now(timezone.utc)` elsewhere (e.g.
    # `authorization.sessions.is_session_valid`,
    # `monitoring.service`) raises TypeError. Same normalization
    # pattern already used in audit/hash_chain.py, intent/canonicalizer.py,
    # and intent/schema.py for this exact BSON behavior.
    expires_at = doc["expires_at"]
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return SessionState(
        session_id=doc["_id"],
        user_id=doc["user_id"],
        device_id=doc["device_id"],
        expires_at=expires_at,
        revoked=doc.get("revoked", False),
        version=doc.get("version", 1),
    )


class MongoSessionRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def get_or_create(self, session_id: str, user_id: int, device_id: str, ttl, now=None):
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id},
            {
                "$setOnInsert": {
                    "user_id": user_id,
                    "device_id": device_id,
                    "expires_at": (now or datetime.now(timezone.utc)) + ttl,
                    "revoked": False,
                    "version": 1,
                }
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        return _to_session_state(doc)

    def get(self, session_id: str) -> SessionState | None:
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one({"_id": session_id})
        return _to_session_state(doc) if doc is not None else None

    def revoke(self, session_id: str) -> SessionState:
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id},
            {"$set": {"revoked": True}},
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            raise KeyError(f"no session '{session_id}'")
        return _to_session_state(doc)

    def refresh(self, session_id: str, ttl, now=None) -> SessionState:
        """Normal refresh: extends expiry for an ACTIVE session only.
        Filtering on `revoked: False` in the query means the update is
        a no-op against an already-revoked document — nothing about
        this call can flip `revoked` back to False. If the session
        exists but is revoked, `SessionRevokedError` is raised instead
        and the stored document is left completely untouched."""
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id, "revoked": {"$ne": True}},
            {
                "$set": {
                    "expires_at": (now or datetime.now(timezone.utc)) + ttl,
                },
                "$inc": {"version": 1},
            },
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            existing = self._db[AUTH_SESSIONS_COLLECTION].find_one({"_id": session_id})
            if existing is None:
                raise KeyError(f"no session '{session_id}'")
            if existing.get("revoked"):
                raise SessionRevokedError(session_id)
            raise KeyError(f"no session '{session_id}'")
        return _to_session_state(doc)

    def reauthorize(self, session_id: str, ttl, now=None) -> SessionState:
        """Establish a fresh authorized session after explicit
        re-authentication has already been verified by the caller:
        un-revokes, extends expiry, and bumps `version`. Only ever
        invoked from the dedicated re-authentication endpoint."""
        doc = self._db[AUTH_SESSIONS_COLLECTION].find_one_and_update(
            {"_id": session_id},
            {
                "$set": {
                    "revoked": False,
                    "expires_at": (now or datetime.now(timezone.utc)) + ttl,
                },
                "$inc": {"version": 1},
            },
            return_document=ReturnDocument.AFTER,
        )
        if doc is None:
            raise KeyError(f"no session '{session_id}'")
        return _to_session_state(doc)


# ---------------------------------------------------------------------
# Continuous monitoring (session-wide, not operation-specific — see
# `monitoring/`). Satisfies `monitoring.service.MonitoringRepository`.
# ---------------------------------------------------------------------

def _thresholds_to_doc(thresholds: MonitoringThresholds) -> dict:
    return {
        "warning_after": thresholds.warning_after,
        "risk_increase_after": thresholds.risk_increase_after,
        "reauth_required_after": thresholds.reauth_required_after,
        "invalidate_after": thresholds.invalidate_after,
    }


def _thresholds_from_doc(doc: dict) -> MonitoringThresholds:
    return MonitoringThresholds(
        warning_after=doc["warning_after"],
        risk_increase_after=doc["risk_increase_after"],
        reauth_required_after=doc["reauth_required_after"],
        invalidate_after=doc["invalidate_after"],
    )


def _to_monitoring_record(doc: dict) -> MonitoringSessionRecord:
    return MonitoringSessionRecord(
        monitoring_session_id=doc["_id"],
        user_id=doc["user_id"],
        device_id=doc["device_id"],
        session_id=doc["session_id"],
        intent_id=doc.get("intent_id"),
        status=MonitoringStatus(doc["status"]),
        consecutive_face_failures=doc["consecutive_face_failures"],
        thresholds=_thresholds_from_doc(doc["thresholds"]),
        started_at=doc["started_at"],
        updated_at=doc["updated_at"],
        stopped=doc.get("stopped", False),
        repeated_denied_requests=doc.get("repeated_denied_requests", 0),
        device_revoked_by_monitoring=doc.get("device_revoked_by_monitoring", False),
        audit_tamper_alerted=doc.get("audit_tamper_alerted", False),
        revoked_at_session_version=doc.get("revoked_at_session_version"),
        last_face_present=doc.get("last_face_present", False),
        last_face_match_confidence=doc.get("last_face_match_confidence"),
        last_liveness=doc.get("last_liveness", False),
        last_camera_available=doc.get("last_camera_available", False),
        last_identity_state=IdentityCheckState(doc.get("last_identity_state", "no_face")),
        last_expression_hint=doc.get("last_expression_hint"),
        last_reason_code=doc.get("last_reason_code"),
        last_reason=doc.get("last_reason"),
        snapshot_revision=doc.get("snapshot_revision", 0),
        check_count=doc.get("check_count", 0),
        successful_face_verifications=doc.get("successful_face_verifications", 0),
        face_liveness_failures=doc.get("face_liveness_failures", 0),
        warning_occurrences=doc.get("warning_occurrences", 0),
        recovery_count=doc.get("recovery_count", 0),
        camera_interruptions=doc.get("camera_interruptions", 0),
        highest_security_state=doc.get("highest_security_state", "SECURE"),
        last_security_state=doc.get("last_security_state", "SECURE"),
        final_security_state=doc.get("final_security_state"),
        overall_security_outcome=doc.get("overall_security_outcome"),
        ended_at=doc.get("ended_at"),
        duration_seconds=doc.get("duration_seconds"),
    )


class MongoMonitoringRepository:
    def __init__(self, db: Database) -> None:
        self._db = db

    def create(
        self, user_id, device_id, session_id, intent_id, thresholds, now
    ) -> MonitoringSessionRecord:
        monitoring_session_id = uuid.uuid4().hex
        doc = {
            "_id": monitoring_session_id,
            "user_id": user_id,
            "device_id": device_id,
            "session_id": session_id,
            "intent_id": intent_id,
            "status": MonitoringStatus.ACTIVE.value,
            "consecutive_face_failures": 0,
            "thresholds": _thresholds_to_doc(thresholds),
            "started_at": now,
            "updated_at": now,
            "stopped": False,
            "repeated_denied_requests": 0,
            "device_revoked_by_monitoring": False,
            "audit_tamper_alerted": False,
            "revoked_at_session_version": None,
            "last_face_present": False,
            "last_face_match_confidence": None,
            "last_liveness": False,
            "last_camera_available": False,
            "last_identity_state": "no_face",
            "last_expression_hint": None,
            "last_reason_code": None,
            "last_reason": None,
            "snapshot_revision": 0,
            "check_count": 0,
            "successful_face_verifications": 0,
            "face_liveness_failures": 0,
            "warning_occurrences": 0,
            "recovery_count": 0,
            "camera_interruptions": 0,
            "highest_security_state": "SECURE",
            "last_security_state": "SECURE",
            "final_security_state": None,
            "overall_security_outcome": None,
            "ended_at": None,
            "duration_seconds": None,
        }
        self._db[MONITORING_SESSIONS_COLLECTION].insert_one(doc)
        return _to_monitoring_record(doc)

    def get(self, monitoring_session_id: str) -> MonitoringSessionRecord | None:
        doc = self._db[MONITORING_SESSIONS_COLLECTION].find_one({"_id": monitoring_session_id})
        return _to_monitoring_record(doc) if doc is not None else None

    def update(self, record: MonitoringSessionRecord) -> MonitoringSessionRecord:
        self._db[MONITORING_SESSIONS_COLLECTION].update_one(
            {"_id": record.monitoring_session_id},
            {
                "$set": {
                    "status": record.status.value,
                    "consecutive_face_failures": record.consecutive_face_failures,
                    "updated_at": record.updated_at,
                    "stopped": record.stopped,
                    "repeated_denied_requests": record.repeated_denied_requests,
                    "device_revoked_by_monitoring": record.device_revoked_by_monitoring,
                    "audit_tamper_alerted": record.audit_tamper_alerted,
                    "revoked_at_session_version": record.revoked_at_session_version,
                    "last_face_present": record.last_face_present,
                    "last_face_match_confidence": record.last_face_match_confidence,
                    "last_liveness": record.last_liveness,
                    "last_camera_available": record.last_camera_available,
                    "last_identity_state": record.last_identity_state.value,
                    "last_expression_hint": record.last_expression_hint,
                    "last_reason_code": record.last_reason_code,
                    "last_reason": record.last_reason,
                    "snapshot_revision": record.snapshot_revision,
                    "check_count": record.check_count,
                    "successful_face_verifications": record.successful_face_verifications,
                    "face_liveness_failures": record.face_liveness_failures,
                    "warning_occurrences": record.warning_occurrences,
                    "recovery_count": record.recovery_count,
                    "camera_interruptions": record.camera_interruptions,
                    "highest_security_state": record.highest_security_state,
                    "last_security_state": record.last_security_state,
                    "final_security_state": record.final_security_state,
                    "overall_security_outcome": record.overall_security_outcome,
                    "ended_at": record.ended_at,
                    "duration_seconds": record.duration_seconds,
                }
            },
        )
        return record

    def append_event(self, event: MonitoringEvent) -> None:
        snap = event.snapshot
        doc = {
            "_id": get_next_id(MONITORING_EVENTS_COLLECTION),
            "monitoring_session_id": event.monitoring_session_id,
            "event_type": event.event_type,
            "snapshot": snap.as_dict(),
            "timestamp": snap.timestamp,
        }
        self._db[MONITORING_EVENTS_COLLECTION].insert_one(doc)

    def list_all(self) -> Sequence[MonitoringSessionRecord]:
        cursor = self._db[MONITORING_SESSIONS_COLLECTION].find({}).sort("updated_at", -1)
        return tuple(_to_monitoring_record(doc) for doc in cursor)

    def get_by_session(self, session_id: str) -> MonitoringSessionRecord | None:
        doc = self._db[MONITORING_SESSIONS_COLLECTION].find_one(
            {"session_id": session_id, "stopped": {"$ne": True}},
            sort=[("updated_at", -1)],
        )
        return _to_monitoring_record(doc) if doc is not None else None

    def list_events(self, monitoring_session_id: str) -> Sequence[MonitoringEvent]:
        cursor = self._db[MONITORING_EVENTS_COLLECTION].find(
            {"monitoring_session_id": monitoring_session_id}
        ).sort("_id", 1)
        events = []
        for doc in cursor:
            snap = doc["snapshot"]
            events.append(
                MonitoringEvent(
                    monitoring_session_id=doc["monitoring_session_id"],
                    event_type=doc["event_type"],
                    snapshot=MonitoringSnapshot(
                        monitoring_session_id=snap["monitoring_session_id"],
                        snapshot_revision=snap.get("snapshot_revision", 0),
                        current_user=snap["current_user"],
                        current_device=snap["current_device"],
                        current_session=snap["current_session"],
                        status=MonitoringStatus(snap["status"]),
                        face_present=snap["face_present"],
                        face_match_confidence=snap["face_match_confidence"],
                        liveness=snap["liveness"],
                        current_intent=snap["current_intent"],
                        current_lifecycle=snap["current_lifecycle"],
                        current_risk=RiskLevel(snap["current_risk"]),
                        risk_score=snap["risk_score"],
                        current_authorization_state=snap["current_authorization_state"],
                        authorization_state_hash=snap["authorization_state_hash"],
                        consecutive_face_failures=snap["consecutive_face_failures"],
                        warnings=tuple(snap.get("warnings", ())),
                        expression_hint=snap.get("expression_hint"),
                        timestamp=doc["timestamp"],
                        security_state=SecurityPostureState(snap.get("security_state", "normal")),
                        identity_state=IdentityCheckState(snap.get("identity_state", "no_face")),
                        reason_code=snap.get("reason_code"),
                        reason=snap.get("reason"),
                        audit_chain_intact=snap.get("audit_chain_intact", True),
                    ),
                )
            )
        return events


class IntentLifecycleLookup:
    """Adapts `IntentRepository` to `monitoring.service.LifecycleLookup`."""

    def __init__(self, intent_repository: IntentRepository) -> None:
        self._intents = intent_repository

    def current_lifecycle_state(self, intent_id: int) -> str | None:
        row = self._intents.get_by_id(intent_id)
        return row.lifecycle_state.value if row is not None else None

class MongoTrustedLocationRepository:
    """Mongo-backed `policy.geofence.TrustedLocationRepository`. One
    document per user, keyed by user id — `set()` always overwrites
    (upsert), never appends, so no location history accumulates."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def get(self, user_id: int) -> TrustedLocation | None:
        doc = self._db[TRUSTED_LOCATIONS_COLLECTION].find_one({"_id": user_id})
        if doc is None:
            return None
        established_at = doc["established_at"]
        if established_at.tzinfo is None:
            established_at = established_at.replace(tzinfo=timezone.utc)
        return TrustedLocation(
            user_id=user_id,
            latitude=doc["latitude"],
            longitude=doc["longitude"],
            accuracy_m=doc.get("accuracy_m"),
            established_at=established_at,
        )

    def set(self, location: TrustedLocation) -> TrustedLocation:
        self._db[TRUSTED_LOCATIONS_COLLECTION].find_one_and_update(
            {"_id": location.user_id},
            {
                "$set": {
                    "latitude": location.latitude,
                    "longitude": location.longitude,
                    "accuracy_m": location.accuracy_m,
                    "established_at": location.established_at,
                }
            },
            upsert=True,
        )
        return location

    def clear(self, user_id: int) -> None:
        self._db[TRUSTED_LOCATIONS_COLLECTION].delete_one({"_id": user_id})

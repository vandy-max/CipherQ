"""
MongoDB document representations.

These are plain dataclasses, not an ORM. MongoDB is schemaless, so
nothing here is "mapped" the way SQLAlchemy models were — these
classes exist so repositories (and the callers that consume their
return values, e.g. `row.id`, `row.username`, `row.lifecycle_state`)
keep working with typed attribute access instead of raw dicts,
without any call sites having to change.

Each class has a `from_document(doc)` constructor that builds an
instance from a raw MongoDB document (a `dict`), and the field names
match the previous PostgreSQL columns exactly.

Notes on a couple of carried-over choices:

- `Intent.current_version_id` / `IntentVersion.intent_id` are stored
  as plain integer references (no real foreign key in MongoDB) —
  the same circular-reference shape as before, just without a DB-level
  constraint enforcing it.
- No document here ever has a field for a raw or derived encryption
  key. `encryption_records` stores only ciphertext/nonce/tag/intent
  linkage, per the "never store the raw encryption key" requirement.
- `_id` on every document is an application-assigned integer (see
  `database.session.get_next_id`), not MongoDB's default ObjectId, so
  that `int`-typed id fields in `api/schemas.py` continue to work
  unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from intent.lifecycle import IntentState

# ---------------------------------------------------------------------
# Collection names
# ---------------------------------------------------------------------

USERS_COLLECTION = "users"
SESSIONS_COLLECTION = "sessions"
FACE_AUTH_LOGS_COLLECTION = "face_auth_logs"
INTENTS_COLLECTION = "intents"
INTENT_VERSIONS_COLLECTION = "intent_versions"
POLICIES_COLLECTION = "policies"
ENCRYPTION_RECORDS_COLLECTION = "encryption_records"
AUDIT_LOGS_COLLECTION = "audit_logs"
RISK_ASSESSMENTS_COLLECTION = "risk_assessments"
# New in the continuous-authorization architecture. Distinct from the
# pre-existing, currently-unused SESSIONS_COLLECTION above: these are
# keyed by the client-supplied `device_id`/`session_id` strings that
# already appear in every CID, not by an application-assigned integer
# id, since callers (and the authorization service) always address
# them by that string.
DEVICES_COLLECTION = "authz_devices"
AUTH_SESSIONS_COLLECTION = "authz_sessions"
# Continuous-monitoring session state + its append-only heartbeat/event
# log (see `monitoring/`). Keyed by the server-generated
# `monitoring_session_id` — distinct from AUTH_SESSIONS_COLLECTION's
# `session_id`, which is the client-supplied CID field.
MONITORING_SESSIONS_COLLECTION = "monitoring_sessions"
MONITORING_EVENTS_COLLECTION = "monitoring_events"

# Trusted-location geofence (Part 2/3, foundation-security fix pass).
# One document per user — enrollment OVERWRITES, never appends, so no
# location history is ever retained (explicit requirement).
TRUSTED_LOCATIONS_COLLECTION = "trusted_locations"

# Qira security incidents (Part 13/14 of the Qira brief). One document
# per CRITICAL-severity automatic action (or admin-triggered manual
# revoke) — this is the Admin Dashboard's "Security Incident" queue.
# Never contains secrets/tokens/face embeddings — only the same safe
# fields already surfaced via QiraContext/QiraDecision.
# Qira security incidents (Part 13/14 of the Qira brief). One document
# per CRITICAL-severity automatic action (or admin-triggered manual
# revoke) — this is the Admin Dashboard's "Security Incident" queue.
# Never contains secrets/tokens/face embeddings — only the same safe
# fields already surfaced via QiraContext/QiraDecision.
SECURITY_INCIDENTS_COLLECTION = "security_incidents"

# Reauthorization requests: a user whose DEVICE (not just session) was
# revoked by continuous monitoring cannot self-service restore access
# (see authorization/reauth_requests.py docstring) — they file a
# request here instead, which the Admin Dashboard's "Access Requests"
# tab surfaces for an admin to approve/reject. One document per
# request; a new request is opened each time a user asks again after
# a prior one was resolved.
REAUTH_REQUESTS_COLLECTION = "reauth_requests"


@dataclass
class User:
    id: int
    username: str
    email: str
    password_hash: str
    salt: str
    role: str = "user"
    face_descriptor: list | None = None
    created_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "User":
        return cls(
            id=doc["_id"],
            username=doc["username"],
            email=doc["email"],
            password_hash=doc["password_hash"],
            salt=doc["salt"],
            role=doc.get("role", "user"),
            face_descriptor=doc.get("face_descriptor"),
            created_at=doc.get("created_at"),
        )


@dataclass
class Session:
    id: int
    user_id: int
    device_id: str
    expires_at: datetime
    issued_at: datetime | None = None
    revoked: bool = False

    @classmethod
    def from_document(cls, doc: dict) -> "Session":
        return cls(
            id=doc["_id"],
            user_id=doc["user_id"],
            device_id=doc["device_id"],
            expires_at=doc["expires_at"],
            issued_at=doc.get("issued_at"),
            revoked=doc.get("revoked", False),
        )


@dataclass
class FaceAuthLog:
    """Identity/liveness verification only — never expression/emotion."""

    id: int
    user_id: int
    confidence_score: float
    verified: bool
    device_id: str
    created_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "FaceAuthLog":
        return cls(
            id=doc["_id"],
            user_id=doc["user_id"],
            confidence_score=doc["confidence_score"],
            verified=doc["verified"],
            device_id=doc["device_id"],
            created_at=doc.get("created_at"),
        )


@dataclass
class Intent:
    id: int
    canonical_hash: str
    lifecycle_state: IntentState
    created_by: int
    current_version_id: int | None = None
    created_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "Intent":
        return cls(
            id=doc["_id"],
            canonical_hash=doc["canonical_hash"],
            lifecycle_state=IntentState(doc["lifecycle_state"]),
            created_by=doc["created_by"],
            current_version_id=doc.get("current_version_id"),
            created_at=doc.get("created_at"),
        )


@dataclass
class IntentVersion:
    """Append-only. Never update a document here — insert a new one."""

    id: int
    intent_id: int
    version_number: int
    cid_json: str
    canonical_hash: str
    author: str
    reason: str
    created_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "IntentVersion":
        return cls(
            id=doc["_id"],
            intent_id=doc["intent_id"],
            version_number=doc["version_number"],
            cid_json=doc["cid_json"],
            canonical_hash=doc["canonical_hash"],
            author=doc["author"],
            reason=doc["reason"],
            created_at=doc.get("created_at"),
        )


@dataclass
class Policy:
    id: int
    name: str
    rule_type: str
    config_json: dict
    active: bool = True
    created_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "Policy":
        return cls(
            id=doc["_id"],
            name=doc["name"],
            rule_type=doc["rule_type"],
            config_json=doc.get("config_json", {}),
            active=doc.get("active", True),
            created_at=doc.get("created_at"),
        )


@dataclass
class EncryptionRecord:
    """Ciphertext + AEAD metadata only. No key material, ever."""

    id: int
    ciphertext: bytes
    nonce: bytes
    auth_tag: bytes
    intent_hash: str
    intent_version_id: int
    created_by: int
    created_at: datetime | None = None
    # Authorization-state hash this record was bound to at encryption
    # time (see authorization.state). Public metadata, not secret —
    # stored so decrypt can explicitly compare it against the current
    # state before attempting AES-GCM. Empty for records created
    # before this field existed.
    authorization_state_hash: str = ""

    @classmethod
    def from_document(cls, doc: dict) -> "EncryptionRecord":
        return cls(
            id=doc["_id"],
            ciphertext=doc["ciphertext"],
            nonce=doc["nonce"],
            auth_tag=doc["auth_tag"],
            intent_hash=doc["intent_hash"],
            intent_version_id=doc["intent_version_id"],
            created_by=doc["created_by"],
            created_at=doc.get("created_at"),
            authorization_state_hash=doc.get("authorization_state_hash", ""),
        )


@dataclass
class AuditLog:
    """Hash-chained, tamper-evident audit trail."""

    id: int
    action: str
    result: str
    prev_log_hash: str
    current_log_hash: str
    timestamp: datetime | None = None
    user_id: int | None = None
    intent_hash: str | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "AuditLog":
        return cls(
            id=doc["_id"],
            action=doc["action"],
            result=doc["result"],
            prev_log_hash=doc["prev_log_hash"],
            current_log_hash=doc["current_log_hash"],
            timestamp=doc.get("timestamp"),
            user_id=doc.get("user_id"),
            intent_hash=doc.get("intent_hash"),
        )


@dataclass
class RiskAssessment:
    id: int
    user_id: int
    session_id: str
    score: float
    level: str
    factors_json: dict
    created_at: datetime | None = None

    @classmethod
    def from_document(cls, doc: dict) -> "RiskAssessment":
        return cls(
            id=doc["_id"],
            user_id=doc["user_id"],
            session_id=doc["session_id"],
            score=doc["score"],
            level=doc["level"],
            factors_json=doc.get("factors_json", {}),
            created_at=doc.get("created_at"),
        )


@dataclass
class DeviceDoc:
    """Persisted counterpart of `authorization.devices.DeviceStatus`."""

    device_id: str
    revoked: bool = False

    @classmethod
    def from_document(cls, doc: dict) -> "DeviceDoc":
        return cls(device_id=doc["_id"], revoked=doc.get("revoked", False))


@dataclass
class AuthSessionDoc:
    """Persisted counterpart of `authorization.sessions.SessionState`."""

    session_id: str
    user_id: int
    device_id: str
    expires_at: datetime
    revoked: bool = False
    version: int = 1

    @classmethod
    def from_document(cls, doc: dict) -> "AuthSessionDoc":
        return cls(
            session_id=doc["_id"],
            user_id=doc["user_id"],
            device_id=doc["device_id"],
            expires_at=doc["expires_at"],
            revoked=doc.get("revoked", False),
            version=doc.get("version", 1),
        )

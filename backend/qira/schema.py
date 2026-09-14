"""
Structured types shared by every stage of the Qira pipeline
(context -> deterministic baseline -> AI assessment -> merged
decision). Keeping these as plain enums/dataclasses — not whatever
shape an LLM happens to return — is what makes it possible to
validate the AI's output server-side (Part 9 of the brief) instead of
letting a model's free-form text reach an enforcement code path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class SecurityState(str, Enum):
    """The ONE authoritative current-state value shown everywhere
    (topbar badge, monitoring dropdown, dashboard card, warning
    banner, Qira). Deliberately only three values — see Part 3/4 of
    the brief. `COMPROMISED` covers both "reauthenticate" and "revoke"
    severities; the detailed reason/severity explains which."""

    SECURE = "SECURE"
    SECURITY_WARNING = "SECURITY_WARNING"
    COMPROMISED = "COMPROMISED"


class TamperSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Total ordering used to merge the deterministic baseline with Qira's
# advisory assessment — never take whichever is LOWER.
_SEVERITY_ORDER = {
    TamperSeverity.LOW: 0,
    TamperSeverity.MEDIUM: 1,
    TamperSeverity.HIGH: 2,
    TamperSeverity.CRITICAL: 3,
}


def max_severity(a: TamperSeverity, b: TamperSeverity) -> TamperSeverity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


class RecommendedAction(str, Enum):
    NONE = "NONE"
    MONITOR = "MONITOR"
    REAUTHENTICATE = "REAUTHENTICATE"
    REVOKE = "REVOKE"


_ACTION_ORDER = {
    RecommendedAction.NONE: 0,
    RecommendedAction.MONITOR: 1,
    RecommendedAction.REAUTHENTICATE: 2,
    RecommendedAction.REVOKE: 3,
}


def max_action(a: RecommendedAction, b: RecommendedAction) -> RecommendedAction:
    return a if _ACTION_ORDER[a] >= _ACTION_ORDER[b] else b


# Severity -> overall UI state, exactly per Part 10 of the brief.
SEVERITY_TO_STATE: dict[TamperSeverity, SecurityState] = {
    TamperSeverity.LOW: SecurityState.SECURE,
    TamperSeverity.MEDIUM: SecurityState.SECURITY_WARNING,
    TamperSeverity.HIGH: SecurityState.COMPROMISED,
    TamperSeverity.CRITICAL: SecurityState.COMPROMISED,
}


@dataclass(frozen=True)
class QiraContext:
    """Safe, minimal current-security-context snapshot handed to the
    AI provider AND returned by `GET /api/security/context`. Every
    field here is already-derived/coarse — never a secret, token,
    cookie, face embedding, private key, or raw location history (see
    Part 7 of the brief)."""

    user_id: int
    user_role: str
    monitoring_session_id: str
    device_id: str
    session_id: str

    monitoring_status: str          # active | warning | reauth_required | revoked
    security_posture: str           # normal | warning | compromised | revoked (existing posture)
    identity_state: str
    face_present: bool
    liveness: bool
    consecutive_face_failures: int

    device_revoked: bool
    session_revoked: bool

    intent_id: int | None
    intent_lifecycle_state: str | None

    risk_level: str
    risk_score: float

    audit_chain_intact: bool
    recent_event_types: tuple[str, ...]  # coarse recent action names only, no payloads

    location_permission_state: str | None = None  # "granted" | "denied" | "not_requested" | None

    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "user_role": self.user_role,
            "monitoring_session_id": self.monitoring_session_id,
            "device_id": self.device_id,
            "session_id": self.session_id,
            "monitoring_status": self.monitoring_status,
            "security_posture": self.security_posture,
            "identity_state": self.identity_state,
            "face_present": self.face_present,
            "liveness": self.liveness,
            "consecutive_face_failures": self.consecutive_face_failures,
            "device_revoked": self.device_revoked,
            "session_revoked": self.session_revoked,
            "intent_id": self.intent_id,
            "intent_lifecycle_state": self.intent_lifecycle_state,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "audit_chain_intact": self.audit_chain_intact,
            "recent_event_types": list(self.recent_event_types),
            "location_permission_state": self.location_permission_state,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass(frozen=True)
class QiraAssessment:
    """Exactly the structured shape from Part 9 of the brief. This is
    what the AI provider is asked to return, and what
    `provider.py`/`service.py` validate before it's allowed anywhere
    near an enforcement decision."""

    security_state: SecurityState
    severity: TamperSeverity
    reason: str
    confidence: float
    recommended_action: RecommendedAction
    signals: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "security_state": self.security_state.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action.value,
            "signals": list(self.signals),
        }


@dataclass(frozen=True)
class QiraDecision:
    """Final, backend-validated decision after merging the
    deterministic baseline with Qira's (optional) advisory assessment,
    and after the fail-safe policy in `policy.py` has run. This is the
    ONLY thing allowed to reach an enforcement code path — never the
    raw AI response."""

    security_state: SecurityState
    severity: TamperSeverity
    recommended_action: RecommendedAction
    enforced_action: RecommendedAction  # what was ACTUALLY enforced (may be more conservative)
    reason: str
    signals: tuple[str, ...]
    ai_available: bool
    ai_confidence: float | None
    ai_explanation: str | None
    baseline_severity: TamperSeverity
    escalated_by_ai: bool
    # Per-session risk telemetry is returned with the Qira decision so the
    # UI can display the actual score/level alongside the verdict.
    risk_level: str
    risk_score: float
    # Audit integrity is a separate system-level control. It is deliberately
    # not flattened into the per-session Qira security_state.
    audit_chain_intact: bool
    incident_id: int | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict:
        return {
            "security_state": self.security_state.value,
            "severity": self.severity.value,
            "recommended_action": self.recommended_action.value,
            "enforced_action": self.enforced_action.value,
            "reason": self.reason,
            "signals": list(self.signals),
            "ai_available": self.ai_available,
            "ai_confidence": self.ai_confidence,
            "ai_explanation": self.ai_explanation,
            "baseline_severity": self.baseline_severity.value,
            "escalated_by_ai": self.escalated_by_ai,
            "risk_level": self.risk_level,
            "risk_score": self.risk_score,
            "audit_chain_intact": self.audit_chain_intact,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat(),
        }

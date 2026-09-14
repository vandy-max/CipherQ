"""
Risk engine: weighted factors -> Low/Medium/High/Critical -> action.

Phase 4 mapping (see PHASE 4 brief, "RISK LEVELS"):

    LOW      -> NORMAL                      -> proceed
    MEDIUM   -> WARNING                     -> require face re-verification
                                                (identity only, see
                                                authentication/ — never
                                                expression/emotion)
    HIGH     -> REAUTHENTICATION / RESTRICTED -> reject this request,
                                                demand step-up before
                                                anything further proceeds
    CRITICAL -> REVOCATION / CRYPTO BLOCK   -> reject AND revoke the
                                                current device/session so
                                                future encrypt/decrypt is
                                                rejected without a fresh
                                                authorization

Authentication (proving identity once) and authorization-to-decrypt
(is this still safe right now) are different questions. A correctly
authenticated user can still accumulate risk after login — that's the
whole point of continuous monitoring (see `monitoring/service.py`).
This engine never concludes anything about whether a person is
"malicious"; it only scores *behavioral/contextual signals* against
configurable thresholds and returns an action.

`face_confidence` is the one place this project intentionally departs
from the reference project: the reference folded face *expression*
into the encryption key itself. Here, face-auth contributes only an
identity-verification confidence score to risk, and never touches key
derivation or the CID. Facial *expression* and a single, isolated face
failure are deliberately never enough on their own to raise risk to
HIGH/CRITICAL — see `repeated_face_failures` below, which requires
*repeated* failures, and the module docstring of `monitoring/state.py`.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAction(str, Enum):
    DECRYPT = "decrypt"
    REQUIRE_FACE_VERIFICATION = "require_face_verification"
    REJECT = "reject"
    REVOKE = "revoke"


_ACTION_BY_LEVEL: dict[RiskLevel, RiskAction] = {
    RiskLevel.LOW: RiskAction.DECRYPT,
    RiskLevel.MEDIUM: RiskAction.REQUIRE_FACE_VERIFICATION,
    RiskLevel.HIGH: RiskAction.REJECT,
    RiskLevel.CRITICAL: RiskAction.REVOKE,
}

FACE_CONFIDENCE_THRESHOLD = 0.6
MEDIUM_RISK_THRESHOLD = 30.0
HIGH_RISK_THRESHOLD = 60.0
CRITICAL_RISK_THRESHOLD = 90.0

_MAX_FAILED_LOGINS_COUNTED = 5
_MAX_RAPID_ACCESS_COUNTED = 5
_MAX_POLICY_FAILURES_COUNTED = 4
_MAX_DENIED_REQUESTS_COUNTED = 5
_MAX_FACE_FAILURES_COUNTED = 5

_DEFAULT_WEIGHTS = {
    "qber": 40.0,
    "failed_login": 8.0,
    "low_face_confidence": 30.0,
    "device_mismatch": 30.0,
    "session_expired": 35.0,
    "rapid_access": 6.0,
    "policy_failure": 15.0,
    # -- Phase 4 additions: continuous-monitoring / behavioral signals --
    "unusual_resource_access": 20.0,
    "unusual_operation": 15.0,
    "sensitive_resource_access": 20.0,
    "repeated_denied_requests": 20.0,
    "repeated_face_failures": 12.0,
    "device_changed": 25.0,
    "session_changed": 15.0,
    "intent_changed": 10.0,
    "lifecycle_changed": 10.0,
    "authorization_changed": 15.0,
    # Revoked device/session is treated as an outright critical signal
    # (weight alone clears CRITICAL_RISK_THRESHOLD), not just "high".
    "revoked_device_or_session": 100.0,
}


@dataclass(frozen=True)
class RiskFactors:
    qber: float = 0.0
    failed_login_count: int = 0
    face_confidence: float | None = None  # None = face auth not attempted this session
    device_mismatch: bool = False
    session_expired: bool = False
    rapid_access_attempts: int = 0
    policy_failure_count: int = 0

    # -- Phase 4: continuous risk / behavioral signals. All default to
    # "nothing unusual" so every existing call site is unaffected. A
    # single occurrence of most of these is informational only —
    # "repeated_*" fields are counts, everything else is a per-request
    # boolean flag describing what changed *since the last known-good
    # state*, fed in by the monitoring/authorization layer, never
    # inferred here. --
    unusual_resource_access: bool = False
    unusual_operation: bool = False
    sensitive_resource_access: bool = False
    repeated_denied_requests: int = 0
    repeated_face_failures: int = 0
    device_changed: bool = False
    session_changed: bool = False
    intent_changed: bool = False
    lifecycle_changed: bool = False
    authorization_changed: bool = False
    revoked_device_or_session: bool = False


@dataclass(frozen=True)
class RiskAssessment:
    score: float
    level: RiskLevel
    action: RiskAction
    factors: RiskFactors


class RiskEngine:
    """Weighted-sum risk scorer.

    Both the per-factor weights and the level thresholds are
    constructor-configurable (PHASE 4 requirement: "Make thresholds
    configurable") — every call site that doesn't pass overrides keeps
    exactly today's behavior via the module-level defaults.
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        medium_threshold: float = MEDIUM_RISK_THRESHOLD,
        high_threshold: float = HIGH_RISK_THRESHOLD,
        critical_threshold: float = CRITICAL_RISK_THRESHOLD,
    ) -> None:
        self._weights = {**_DEFAULT_WEIGHTS, **(weights or {})}
        if not (0 <= medium_threshold <= high_threshold <= critical_threshold):
            raise ValueError(
                "risk thresholds must satisfy 0 <= medium <= high <= critical"
            )
        self._medium_threshold = medium_threshold
        self._high_threshold = high_threshold
        self._critical_threshold = critical_threshold

    def assess(self, factors: RiskFactors) -> RiskAssessment:
        w = self._weights
        score = 0.0
        score += min(max(factors.qber, 0.0), 1.0) * w["qber"]
        score += min(factors.failed_login_count, _MAX_FAILED_LOGINS_COUNTED) * w["failed_login"]

        if factors.face_confidence is not None and factors.face_confidence < FACE_CONFIDENCE_THRESHOLD:
            score += w["low_face_confidence"]

        if factors.device_mismatch:
            score += w["device_mismatch"]

        if factors.session_expired:
            score += w["session_expired"]

        score += min(factors.rapid_access_attempts, _MAX_RAPID_ACCESS_COUNTED) * w["rapid_access"]
        score += min(factors.policy_failure_count, _MAX_POLICY_FAILURES_COUNTED) * w["policy_failure"]

        if factors.unusual_resource_access:
            score += w["unusual_resource_access"]
        if factors.unusual_operation:
            score += w["unusual_operation"]
        if factors.sensitive_resource_access:
            score += w["sensitive_resource_access"]
        score += (
            min(factors.repeated_denied_requests, _MAX_DENIED_REQUESTS_COUNTED)
            * w["repeated_denied_requests"]
        )
        score += (
            min(factors.repeated_face_failures, _MAX_FACE_FAILURES_COUNTED)
            * w["repeated_face_failures"]
        )
        if factors.device_changed:
            score += w["device_changed"]
        if factors.session_changed:
            score += w["session_changed"]
        if factors.intent_changed:
            score += w["intent_changed"]
        if factors.lifecycle_changed:
            score += w["lifecycle_changed"]
        if factors.authorization_changed:
            score += w["authorization_changed"]
        if factors.revoked_device_or_session:
            score += w["revoked_device_or_session"]

        if score >= self._critical_threshold:
            level = RiskLevel.CRITICAL
        elif score >= self._high_threshold:
            level = RiskLevel.HIGH
        elif score >= self._medium_threshold:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        return RiskAssessment(
            score=round(score, 2),
            level=level,
            action=_ACTION_BY_LEVEL[level],
            factors=factors,
        )

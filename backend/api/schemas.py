from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Operation = Literal["encrypt", "decrypt", "read", "write", "share", "revoke"]


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    # Self-registration may only ever pick between the two ordinary user
    # tiers — never ADMIN. Enforced twice: the Literal below rejects any
    # other value at the wire/validation layer, and api/routers/auth.py
    # re-checks against rbac.SELF_REGISTERABLE_ROLES before it's used, so
    # a future edit to this schema alone can't silently open the door to
    # self-service admin. Admin accounts only ever come from
    # scripts/seed_admin.py or an existing admin's PUT /api/users/{id}/role.
    role: Optional[Literal["USER_LEVEL_1", "USER_LEVEL_2"]] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class AuthResponse(BaseModel):
    token: str
    user_id: int
    username: str
    role: str


class CIDRequest(BaseModel):
    """Wire format for a CID — mirrors intent.schema.CID exactly."""

    sender: str
    receiver: str
    purpose: str
    resource: str
    operation: Operation
    device_id: str
    session_id: str
    valid_from: datetime
    valid_until: datetime
    classification: Optional[str] = None
    department: Optional[str] = None
    project: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class CreateIntentRequest(BaseModel):
    cid: CIDRequest
    reason: str = "initial creation"


class IntentResponse(BaseModel):
    intent_id: int
    version_number: int
    intent_hash: str
    lifecycle_state: str


class IntentSummaryResponse(BaseModel):
    """One row of `GET /api/intent` — a lightweight listing for the
    Intent History / Admin approval-queue views, distinct from
    `IntentResponse` (the create/transition result) since a listing
    doesn't have a single "version_number just changed" to report.

    Includes the resource/operation/purpose from the intent's own
    recorded CID and the creator's username/role, so the Admin
    Dashboard's approval queue can show what's actually being
    requested rather than just an opaque intent id and hash — nothing
    here is invented, it's all reused from `IntentRepository` and
    `MongoUserRepository`, the same sources the rest of the API
    already trusts for this data.
    """

    intent_id: int
    intent_hash: str
    lifecycle_state: str
    created_by: int
    created_by_username: Optional[str] = None
    created_by_role: Optional[str] = None
    created_at: Optional[datetime] = None
    resource: Optional[str] = None
    operation: Optional[str] = None
    purpose: Optional[str] = None


class IntentResolveResponse(BaseModel):
    """Full authoritative detail for an intent, resolved by its
    canonical hash. Every field here — crucially `valid_from` /
    `valid_until` — comes from the intent's OWN stored CID, never from
    anything the caller supplies. This is what lets the Encryption
    page show "here is what this intent hash actually authorizes"
    without ever trusting a browser-supplied validity window (see fix
    pass section F)."""

    intent_id: int
    intent_hash: str
    lifecycle_state: str
    created_by: int
    created_at: Optional[datetime] = None
    sender: str
    receiver: str
    purpose: str
    resource: str
    operation: str
    device_id: str
    session_id: str
    valid_from: datetime
    valid_until: datetime
    classification: Optional[str] = None
    department: Optional[str] = None
    project: Optional[str] = None
    cid: CIDRequest


class TransitionIntentRequest(BaseModel):
    target_state: str
    reason: str


class ValidateIntentRequest(BaseModel):
    cid: CIDRequest
    intent_id: Optional[int] = None


class PolicyOutcomeResponse(BaseModel):
    rule_name: str
    passed: bool
    reason: Optional[str] = None


class IdentityCheckResponse(BaseModel):
    checked: bool
    verified: Optional[bool] = None
    confidence: Optional[float] = None
    reason: Optional[str] = None


class DeviceCheckResponse(BaseModel):
    device_id: str
    revoked: bool


class SessionCheckResponse(BaseModel):
    session_id: str
    known: bool
    valid: bool
    reason: Optional[str] = None


class IntentValidationResponse(BaseModel):
    valid: bool
    canonicalized_intent: dict[str, Any]
    intent_hash: str
    resource: str
    operation: str
    purpose: str
    valid_from: datetime
    valid_until: datetime
    policy_passed: bool
    policy_outcomes: list[PolicyOutcomeResponse]
    risk_score: float
    risk_level: str
    identity: IdentityCheckResponse
    device: DeviceCheckResponse
    session: SessionCheckResponse
    current_lifecycle: str
    approval_eligible: bool
    reason: Optional[str] = None


class EncryptRequest(BaseModel):
    intent_id: int
    cid: CIDRequest
    plaintext_base64: str
    quantum_key_hex: str
    face_descriptor: Optional[list[float]] = None


class EncryptResponse(BaseModel):
    record_id: int
    intent_id: int
    intent_hash: str
    ciphertext_hex: str
    nonce_hex: str
    auth_tag_hex: str
    authorization_state_hash: str
    intent_lifecycle_state: str
    risk_level: str
    risk_score: float
    # -- Autonomous AI risk analysis (advisory only — see
    # policy/ai_risk_service.py). Never trusted as request input;
    # always backend-computed and included here for transparency. --
    ai_risk_available: bool = False
    ai_risk_confidence: Optional[float] = None
    ai_detected_patterns: list[str] = []
    ai_explanation: Optional[str] = None
    ai_model_type: Optional[str] = None


class DecryptRequest(BaseModel):
    record_id: int
    cid: CIDRequest
    quantum_key_hex: str
    face_descriptor: Optional[list[float]] = None


class DecryptResponse(BaseModel):
    plaintext_base64: str
    risk_level: str
    risk_score: float
    authorization_state_hash: str
    intent_lifecycle_state: str
    ai_risk_available: bool = False
    ai_risk_confidence: Optional[float] = None
    ai_detected_patterns: list[str] = []
    ai_explanation: Optional[str] = None
    ai_model_type: Optional[str] = None


class QuantumGenerateKeyRequest(BaseModel):
    n_qubits: int = 256
    eavesdrop_prob: float = 0.0


class QuantumGenerateKeyResponse(BaseModel):
    quantum_key_hex: str
    qber: float
    sifted_bits: int
    session_aborted: bool
    total_exchanges: int = 0
    qubits_per_circuit: int = 0
    full_circuits: int = 0
    remainder_qubits: int = 0


class AuditLogEntryResponse(BaseModel):
    timestamp: datetime
    user_id: Optional[int]
    action: str
    intent_hash: Optional[str]
    result: str
    current_log_hash: str
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    resource: Optional[str] = None
    operation: Optional[str] = None
    risk: Optional[str] = None
    reason: Optional[str] = None


class AuditVerifyResponse(BaseModel):
    valid: bool
    first_invalid_index: Optional[int]
    reason: Optional[str]
    security_state: Optional[str] = None
    checks: dict[str, bool] = {}
    checked_entries: int = 0


class RiskAssessRequest(BaseModel):
    qber: float = 0.0
    failed_login_count: int = 0
    face_confidence: Optional[float] = None
    device_mismatch: bool = False
    session_expired: bool = False
    rapid_access_attempts: int = 0
    policy_failure_count: int = 0
    # -- Phase 4: continuous risk / behavioral signals --
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


class MLRiskFactorResponse(BaseModel):
    feature: str
    value: float
    weight: float
    contribution: float


class RiskAssessResponse(BaseModel):
    # -- Deterministic engine (policy.risk.RiskEngine) — this is the
    # verdict that is actually enforced. --
    score: float
    level: str
    action: str
    # -- Advisory-only ML signal (policy.ml_risk.MLRiskModel). Never
    # the sole authority; see that module's docstring. A hand-specified
    # prototype model, not trained on real data. --
    ai_risk_probability: float
    ai_risk_level: str
    ai_top_factors: list[MLRiskFactorResponse]
    ai_model_note: str = (
        "Prototype/demo model: hand-specified logistic regression, not trained on "
        "real historical data. Advisory signal only — the deterministic score/level/"
        "action above is what is actually enforced."
    )


class PolicyRequest(BaseModel):
    name: str
    rule_type: str
    config: dict[str, Any]
    active: bool = True


class PolicyResponse(BaseModel):
    id: int
    name: str
    rule_type: str
    config: dict[str, Any]
    active: bool


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str


class UpdateUserRoleRequest(BaseModel):
    role: str


class FaceEnrollRequest(BaseModel):
    descriptor: list[float]


class FaceVerifyRequest(BaseModel):
    descriptor: list[float]


class FaceVerifyResponse(BaseModel):
    verified: bool
    confidence: float
    distance: float


class FaceStatusResponse(BaseModel):
    enrolled: bool


class DeviceStatusResponse(BaseModel):
    device_id: str
    revoked: bool


class DeviceTrustResponse(BaseModel):
    """Reports where a device stands for the CALLING user specifically
    — reuses the existing device-ownership binding
    (`MongoDeviceRepository.get_owner`/`.claim_owner`, already used by
    session establishment to stop one user's session being bound to
    another user's device) rather than inventing a new "trusted
    device" concept from scratch.

    status:
      "trusted" — this device is already owned by the calling user
      "new"     — nobody has claimed this device yet (it will become
                  trusted the moment a session is established on it)
      "foreign" — this device is owned by a DIFFERENT user
      "revoked" — this device has been administratively revoked
                  (takes priority over the above: a revoked device is
                  never reported as trusted, even if the caller owns it)
    """

    device_id: str
    status: str
    revoked: bool
    is_own_device: bool
    has_any_owner: bool


class SessionStatusResponse(BaseModel):
    session_id: str
    device_id: str
    revoked: bool
    expires_at: datetime
    version: int


class RefreshSessionRequest(BaseModel):
    device_id: str
    ttl_minutes: int = 60


class ReauthenticateSessionRequest(BaseModel):
    """Explicit re-authentication: a fresh face descriptor is REQUIRED.
    For a non-admin recovery, `reauth_request_id` identifies the exact
    one-time administrator approval being consumed."""

    device_id: str
    face_descriptor: list[float]
    ttl_minutes: int = 60
    reauth_request_id: int | None = None


class MonitoringStartRequest(BaseModel):
    """Begin a continuous-monitoring session. `face_confidence` must
    come from a face verification the caller already performed
    (e.g. `/api/face/verify`) — this endpoint does not itself verify
    identity, it starts watching a session that has already passed
    LOGIN -> FACE VERIFIED."""

    device_id: str
    session_id: str
    face_confidence: float
    intent_id: Optional[int] = None


class MonitoringHeartbeatRequest(BaseModel):
    monitoring_session_id: str
    face_present: bool
    face_match_confidence: Optional[float] = None
    liveness: bool = True
    # False when the client could not obtain a camera frame at all
    # this tick (permission denied, camera disconnected, tab hidden,
    # etc.) — distinct from `face_present=False`, which means the
    # camera worked but no face was found in the frame.
    camera_available: bool = True
    # Supporting telemetry only — see monitoring/service.py. Never
    # gates a decision and never implies malicious behavior.
    expression_hint: Optional[str] = None


class MonitoringSnapshotResponse(BaseModel):
    monitoring_session_id: str
    current_user: int
    current_device: str
    current_session: str
    status: str
    face_present: bool
    face_match_confidence: Optional[float] = None
    liveness: bool
    current_intent: Optional[int] = None
    current_lifecycle: Optional[str] = None
    current_risk: str
    risk_score: float
    current_authorization_state: str
    authorization_state_hash: str
    consecutive_face_failures: int
    warnings: list[str] = []
    expression_hint: Optional[str] = None
    timestamp: datetime
    security_state: str = "normal"
    identity_state: str = "no_face"
    reason_code: Optional[str] = None
    reason: Optional[str] = None


class MonitoringEventResponse(BaseModel):
    event_type: str
    snapshot: MonitoringSnapshotResponse


class AuthorizationStateRequest(BaseModel):
    cid: CIDRequest
    intent_id: int


class AuthorizationStateResponse(BaseModel):
    """The CURRENT authorization/security state for a given
    (CID, intent) pair — same fields the crypto layer binds into an
    active session, surfaced for inspection/demo purposes."""

    authorized: bool
    authorization_state_hash: Optional[str] = None
    intent_lifecycle_state: Optional[str] = None
    policy_decision_signature: Optional[str] = None
    session_version: Optional[int] = None
    device_id: str
    session_id: str
    rejection_reason: Optional[str] = None


# ---------------------------------------------------------------------
# Trusted Location / Geofence (Part 2/3, foundation-security fix pass)
# ---------------------------------------------------------------------

class EnrollTrustedLocationRequest(BaseModel):
    latitude: float
    longitude: float
    accuracy_m: Optional[float] = None


class TrustedLocationResponse(BaseModel):
    established: bool
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_m: Optional[float] = None
    established_at: Optional[datetime] = None


class CheckLocationRequest(BaseModel):
    # All optional: an absent lat/lon means the browser could not
    # supply a location (permission denied/unavailable) — this is a
    # legitimate, non-malicious "unknown" state, not an error.
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy_m: Optional[float] = None
    radius_m: Optional[float] = None


class LocationCheckResponse(BaseModel):
    status: str  # "trusted" | "outside_trusted_zone" | "unknown" | "not_enrolled"
    distance_m: Optional[float] = None
    radius_m: float
    trusted_location_established: bool


# ---------------------------------------------------------------------
# Qira — CipherQ Security Copilot
# ---------------------------------------------------------------------

class SecurityContextResponse(BaseModel):
    user_id: int
    user_role: str
    monitoring_session_id: str
    device_id: str
    session_id: str
    monitoring_status: str
    security_posture: str
    identity_state: str
    face_present: bool
    liveness: bool
    consecutive_face_failures: int
    device_revoked: bool
    session_revoked: bool
    intent_id: Optional[int] = None
    intent_lifecycle_state: Optional[str] = None
    risk_level: str
    risk_score: float
    audit_chain_intact: bool
    recent_event_types: list[str] = []
    location_permission_state: Optional[str] = None
    timestamp: datetime


class QiraAssessRequest(BaseModel):
    monitoring_session_id: str
    location_permission_state: Optional[str] = None


class QiraDecisionResponse(BaseModel):
    security_state: str        # SECURE | SECURITY_WARNING | COMPROMISED
    severity: str               # LOW | MEDIUM | HIGH | CRITICAL
    recommended_action: str     # NONE | MONITOR | REAUTHENTICATE | REVOKE
    enforced_action: str
    reason: str
    signals: list[str] = []
    ai_available: bool
    ai_confidence: Optional[float] = None
    ai_explanation: Optional[str] = None
    baseline_severity: str
    escalated_by_ai: bool
    risk_level: str = "unknown"
    risk_score: float = 0.0
    audit_chain_intact: bool = True
    incident_id: Optional[int] = None
    timestamp: datetime


class QiraAskRequest(BaseModel):
    monitoring_session_id: str
    question: str


class QiraAskResponse(BaseModel):
    answer: str
    ai_available: bool


class UserRiskOverviewResponse(BaseModel):
    user_id: int
    username: str
    role: str
    monitoring_session_id: Optional[str] = None
    device_id: Optional[str] = None
    authorization_session_id: Optional[str] = None
    monitoring_status: str
    identity_state: Optional[str] = None
    security_state: str
    risk_level: str
    risk_score: Optional[float] = None
    qira_security_state: Optional[str] = None
    qira_severity: Optional[str] = None
    qira_recommended_action: Optional[str] = None
    qira_enforced_action: Optional[str] = None
    qira_reason: Optional[str] = None
    # PART 11/15 — a plain-language reason for the monitoring status
    # itself (device revoked, repeated failures, etc.), independent
    # of Qira's own separate assessment reason above.
    reason: Optional[str] = None
    face_present: bool = False
    face_match_confidence: Optional[float] = None
    liveness: bool = False
    camera_available: bool = False
    reason_code: Optional[str] = None
    consecutive_face_failures: int = 0
    device_revoked: bool = False
    session_revoked: bool = False
    timestamp: datetime


class SecurityIncidentResponse(BaseModel):
    incident_id: int
    user_id: int
    device_id: str
    session_id: str
    monitoring_session_id: str
    severity: str
    security_state: str
    reason: str
    signals: list[str] = []
    action_taken: str
    qira_assessment: Optional[dict] = None
    detected_at: datetime
    resolved: bool
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None


class ResolveSecurityIncidentRequest(BaseModel):
    note: str


# ---------------------------------------------------------------------
# Reauthorization requests (authorization/reauth_requests.py)
# ---------------------------------------------------------------------

class CreateReauthRequestRequest(BaseModel):
    device_id: str
    session_id: str
    message: str = Field(..., min_length=1, max_length=1000)


class ReauthRequestResponse(BaseModel):
    request_id: int
    user_id: int
    username: str
    device_id: str
    session_id: str
    message: str
    status: str
    created_at: datetime
    resolved_by: Optional[int] = None
    resolved_by_username: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None


class ResolveReauthRequestRequest(BaseModel):
    note: Optional[str] = None

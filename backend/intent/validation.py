"""
Automatic intent validation.

This is the "is this intent valid and eligible" question, kept
explicitly separate from two other questions that live elsewhere:

    APPROVAL      — "has the lifecycle service authorized this
                     intent?" (`api/routers/intent.py`'s
                     `/transition` endpoint, backed by
                     `intent.lifecycle`)
    CRYPTOGRAPHY  — "can this APPROVED intent enter the crypto
                     path?" (`api/routers/encryption.py` /
                     `api/routers/decryption.py`, backed by
                     `authorization.AuthorizationService`)

`IntentValidationService` never mutates lifecycle state and never
runs BB84/HKDF/AES — it only reports. It is deliberately built out of
the SAME building blocks the enforcement paths use (the canonicalizer,
`policy.engine.PolicyEngine`, `policy.risk.RiskEngine`, and the
`authorization.devices` / `authorization.sessions` repository
Protocols) so there is exactly one implementation of each check in
the codebase — this module only orchestrates and reports on them.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, Sequence

from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository, is_session_valid
from policy.config import PolicyRow, policy_context_overrides
from policy.engine import PolicyDecision, PolicyEngine
from policy.risk import RiskAssessment, RiskEngine, RiskFactors, RiskLevel
from policy.rules import PolicyContext


class PolicyConfigRepository(Protocol):
    """Satisfied by `api.repositories.PolicyRepository`. Same Protocol
    as `authorization.service.PolicyConfigRepository` — duplicated
    rather than imported cross-module so `intent/` stays independent
    of `authorization/`, matching this module's existing layering."""

    def list_all(self) -> Sequence[PolicyRow]: ...

from .canonicalizer import canonicalize_cid, compute_intent_hash
from .lifecycle import IntentState
from .schema import CID


@dataclass(frozen=True)
class IdentityCheckResult:
    """Identity-verification input to validation. `checked=False`
    means no face-verification probe was supplied with this
    validation request (e.g. a pre-submission check on the Create
    Intent form, before any biometric step runs) — that is reported
    as "not yet checked", never silently treated as passing.
    """

    checked: bool
    verified: bool | None = None
    confidence: float | None = None
    reason: str | None = None

    @classmethod
    def not_attempted(cls) -> "IdentityCheckResult":
        return cls(checked=False, verified=None, confidence=None, reason="not attempted")


@dataclass(frozen=True)
class DeviceCheckResult:
    device_id: str
    revoked: bool


@dataclass(frozen=True)
class SessionCheckResult:
    session_id: str
    known: bool
    valid: bool
    reason: str | None


@dataclass(frozen=True)
class IntentValidationResult:
    """Everything the UI's Intent -> Validation -> Canonicalization ->
    Hash -> Policy -> Risk -> Identity -> Device -> Session ->
    Approval Eligibility -> Lifecycle pipeline needs to render, in one
    object.
    """

    valid: bool
    canonicalized_intent: dict
    intent_hash: str
    resource: str
    operation: str
    purpose: str
    valid_from: datetime
    valid_until: datetime
    policy_result: PolicyDecision
    risk: RiskAssessment
    identity: IdentityCheckResult
    device: DeviceCheckResult
    session: SessionCheckResult
    current_lifecycle: IntentState
    approval_eligible: bool
    reason: str | None = None


class IntentValidationService:
    """Runs the full automatic-validation pipeline (structure through
    approval eligibility) for a CID. Read-only: never persists
    anything and never transitions lifecycle state.
    """

    def __init__(
        self,
        device_repository: DeviceRepository,
        session_repository: SessionRepository,
        policy_engine: PolicyEngine | None = None,
        risk_engine: RiskEngine | None = None,
        policy_config_repository: PolicyConfigRepository | None = None,
    ) -> None:
        self._devices = device_repository
        self._sessions = session_repository
        self._policy_engine = policy_engine or PolicyEngine()
        self._risk_engine = risk_engine or RiskEngine()
        # Optional — see authorization.service.AuthorizationService for
        # why omitting it preserves prior (unrestricted) behavior.
        self._policy_config_repository = policy_config_repository

    def validate(
        self,
        cid: CID,
        *,
        current_lifecycle: IntentState,
        requesting_user_role: str,
        identity: IdentityCheckResult | None = None,
        risk_factors: RiskFactors | None = None,
        now: datetime | None = None,
    ) -> IntentValidationResult:
        # Structure (1) is already enforced by CID's pydantic schema
        # by the time a `CID` instance exists — a caller with a
        # malformed payload never reaches this method. Required
        # fields (5), resource (6), operation (7), and purpose (8)
        # are likewise guaranteed non-empty by `CID`'s own validators.
        now = now or datetime.now(timezone.utc)

        # Parse + canonicalize + hash (2-4) — the one implementation,
        # reused everywhere else in the codebase too.
        canonicalized = canonicalize_cid(cid)
        intent_hash = compute_intent_hash(cid)

        # Validity period (9).
        validity_ok = cid.valid_from <= now <= cid.valid_until

        # Policy (10).
        overrides = {}
        if self._policy_config_repository is not None:
            overrides = policy_context_overrides(self._policy_config_repository.list_all())
        policy_context = PolicyContext(now=now, requesting_user_role=requesting_user_role, **overrides)
        policy_decision = self._policy_engine.evaluate(cid, policy_context)

        # Risk (11). Absent explicit factors, derive a baseline purely
        # from what this validation pass already observed (policy
        # failures) — this is informational only; the real,
        # request-time risk gate is `policy.risk` as invoked from
        # `api/routers/decryption.py`.
        factors = risk_factors or RiskFactors(policy_failure_count=len(policy_decision.failures))
        risk_assessment = self._risk_engine.assess(factors)

        # Identity (12).
        identity_result = identity or IdentityCheckResult.not_attempted()

        # Device (13).
        device_status = self._devices.get_status(cid.device_id)
        device_result = DeviceCheckResult(device_id=cid.device_id, revoked=device_status.revoked)

        # Session (14).
        existing_session = self._sessions.get(cid.session_id)
        if existing_session is None:
            # A session that has never been established is not itself
            # invalid — it will be created on first authorize() call —
            # but it is reported as "not yet known" rather than valid.
            session_result = SessionCheckResult(
                session_id=cid.session_id, known=False, valid=True, reason=None
            )
        else:
            valid, reason = is_session_valid(existing_session, now)
            session_result = SessionCheckResult(
                session_id=cid.session_id, known=True, valid=valid, reason=reason
            )

        # Approval eligibility (15).
        reasons: list[str] = []
        if not validity_ok:
            reasons.append("outside validity period")
        if not policy_decision.passed:
            reasons.append("policy evaluation failed")
        if risk_assessment.level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            reasons.append("risk level too high")
        if device_result.revoked:
            reasons.append(f"device '{device_result.device_id}' is revoked")
        if not session_result.valid:
            reasons.append(f"session invalid: {session_result.reason}")
        if identity_result.checked and identity_result.verified is False:
            reasons.append("identity verification failed")
        if current_lifecycle is not IntentState.DRAFT:
            reasons.append(
                f"intent is already '{current_lifecycle.value}', not eligible for approval"
            )

        approval_eligible = not reasons
        valid = (
            validity_ok
            and policy_decision.passed
            and not device_result.revoked
            and session_result.valid
        )

        return IntentValidationResult(
            valid=valid,
            canonicalized_intent=canonicalized,
            intent_hash=intent_hash,
            resource=cid.resource,
            operation=cid.operation,
            purpose=cid.purpose,
            valid_from=cid.valid_from,
            valid_until=cid.valid_until,
            policy_result=policy_decision,
            risk=risk_assessment,
            identity=identity_result,
            device=device_result,
            session=session_result,
            current_lifecycle=current_lifecycle,
            approval_eligible=approval_eligible,
            reason="; ".join(reasons) if reasons else None,
        )

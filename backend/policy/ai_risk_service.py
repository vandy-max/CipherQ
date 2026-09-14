"""
Autonomous AI-driven risk analysis — the orchestration layer that ties
`context_collector.SecurityContextCollector`, the deterministic
`risk.RiskEngine`, and the advisory `ml_risk.MLRiskModel` together into
one call sites (`/api/encrypt`, `/api/decrypt`) actually use.

Authority model (PHASE 6 of the fix-pass brief, enforced here in code
rather than just in a comment):

    - `RiskEngine` (deterministic, threshold-based) is what decides
      REJECT/REVOKE. Nothing in this module can make it more lenient.
    - `MLRiskModel` (the "AI" layer — see its own module docstring for
      exactly what it is/is not) is advisory. It can only ever make
      the outcome MORE cautious than the deterministic verdict alone
      (nudging DECRYPT up to a step-up challenge when it strongly
      disagrees), never less. It can never turn a REJECT/REVOKE into
      something weaker.
    - If the ML model raises for any reason, this module catches it,
      falls back to the deterministic verdict alone, and says so in
      the result (`ai_available=False`, `model_type` names the
      fallback) — it never lets an AI failure silently allow a
      sensitive request through, and never crashes the request.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from intent.schema import CID

from .context_collector import SecurityContextCollector
from .ml_risk import MLRiskModel
from .risk import RiskAction, RiskEngine, RiskLevel

_ML_MODEL_TYPE = "logistic-regression-prototype (advisory, unverified accuracy)"
_FALLBACK_MODEL_TYPE = "fallback-deterministic-only (ai unavailable)"

# The only nudge this module is allowed to make: escalate a
# DECRYPT-eligible deterministic verdict to a step-up challenge. It
# never escalates all the way to REJECT/REVOKE on its own, and never
# touches a verdict that's already REJECT/REVOKE.
_ESCALATABLE_ACTIONS = frozenset({RiskAction.DECRYPT})


@dataclass(frozen=True)
class AutonomousRiskResult:
    risk_score: float
    risk_level: str
    action: str
    recommended_action: str
    confidence: float | None
    top_risk_factors: tuple[str, ...]
    detected_patterns: tuple[str, ...]
    explanation: str
    signals_analyzed: tuple[str, ...]
    model_type: str
    ai_available: bool
    ai_escalated: bool
    timestamp: datetime


def assess(
    *,
    collector: SecurityContextCollector,
    risk_engine: RiskEngine,
    user_id: int,
    cid: CID,
    face_confidence: float | None,
    ml_model: MLRiskModel | None = None,
    now: datetime | None = None,
    fold_device_session_revocation_into_score: bool = True,
) -> AutonomousRiskResult:
    now = now or datetime.now(timezone.utc)

    context = collector.collect(
        user_id,
        cid,
        face_confidence,
        now=now,
        fold_device_session_revocation_into_score=fold_device_session_revocation_into_score,
    )
    deterministic = risk_engine.assess(context.factors)

    ai_available = False
    confidence: float | None = None
    top_factor_names: tuple[str, ...] = ()
    model_type = _FALLBACK_MODEL_TYPE
    action = deterministic.action
    ai_escalated = False

    model = ml_model if ml_model is not None else MLRiskModel()
    try:
        ml_result = model.assess(context.factors)
        ai_available = True
        confidence = ml_result.probability
        top_factor_names = tuple(c.feature for c in ml_result.top_factors)
        model_type = _ML_MODEL_TYPE

        # Advisory-only escalation: only ever tightens, never loosens,
        # and only ever moves DECRYPT -> step-up (never straight to
        # REJECT/REVOKE — those remain the deterministic engine's call
        # alone, given this model has no measured accuracy).
        if (
            deterministic.action in _ESCALATABLE_ACTIONS
            and ml_result.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ):
            action = RiskAction.REQUIRE_FACE_VERIFICATION
            ai_escalated = True
    except Exception:
        # Fail safe: never let an AI failure crash the request or
        # silently loosen the outcome. Deterministic verdict stands.
        ai_available = False

    if not top_factor_names:
        # Fallback explanation source when the ML layer is unavailable
        # or produced no positive contributors: name whichever
        # collected signals were actually non-default this request.
        top_factor_names = _nonzero_signal_names(context.factors)

    explanation = _build_explanation(
        deterministic_level=deterministic.level,
        ai_available=ai_available,
        ai_escalated=ai_escalated,
        patterns=context.detected_patterns,
        top_factors=top_factor_names,
    )

    return AutonomousRiskResult(
        risk_score=deterministic.score,
        risk_level=deterministic.level.value,
        action=action.value,
        recommended_action=_ACTION_LABEL[action],
        confidence=confidence,
        top_risk_factors=top_factor_names,
        detected_patterns=context.detected_patterns,
        explanation=explanation,
        signals_analyzed=context.signals_analyzed,
        model_type=model_type,
        ai_available=ai_available,
        ai_escalated=ai_escalated,
        timestamp=now,
    )


_ACTION_LABEL = {
    RiskAction.DECRYPT: "proceed",
    RiskAction.REQUIRE_FACE_VERIFICATION: "step_up_required",
    RiskAction.REJECT: "block",
    RiskAction.REVOKE: "block_and_revoke",
}


def _nonzero_signal_names(factors) -> tuple[str, ...]:
    names = []
    for field in (
        "device_mismatch",
        "session_expired",
        "unusual_resource_access",
        "sensitive_resource_access",
        "device_changed",
        "revoked_device_or_session",
    ):
        if getattr(factors, field, False):
            names.append(field)
    if factors.repeated_denied_requests:
        names.append("repeated_denied_requests")
    if factors.repeated_face_failures:
        names.append("repeated_face_failures")
    if factors.failed_login_count:
        names.append("failed_login_count")
    return tuple(names)


def _build_explanation(
    *, deterministic_level: RiskLevel, ai_available: bool, ai_escalated: bool, patterns, top_factors
) -> str:
    parts = [f"deterministic risk level {deterministic_level.value}"]
    if top_factors:
        parts.append("driven by: " + ", ".join(top_factors))
    if patterns:
        parts.append("correlated patterns: " + ", ".join(patterns))
    if not ai_available:
        parts.append("AI advisory layer unavailable — deterministic verdict used alone")
    elif ai_escalated:
        parts.append("AI advisory layer flagged additional risk — step-up required")
    return "; ".join(parts)

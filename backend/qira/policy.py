"""
Deterministic Qira policy — Part 28 ("fail-safe architecture") of the
brief in code form.

This module computes a `TamperSeverity` + `RecommendedAction` baseline
from `QiraContext` ALONE, using only already-authoritative signals
(the existing continuous-monitoring state machine, device/session
revocation, and deterministic risk level). Audit-chain integrity is
reported separately as a system-level control. It never
calls the AI provider and never can be *lowered* by one.

Authority model (mirrors `policy/ai_risk_service.py`'s existing rule
for the advisory ML layer, applied here to the LLM layer):

    - This deterministic baseline is the FLOOR. `service.py` may let
      Qira's AI assessment escalate severity/action above this floor,
      never below it.
    - Only THIS module's signals — never the AI's opinion alone — are
      allowed to produce a CRITICAL/REVOKE baseline. The AI can raise
      MEDIUM up to HIGH (asking for reauthentication) but can never by
      itself manufacture the CRITICAL severity that triggers an actual
      access revocation; that requires a deterministic, confirmed
      session signal (revoked device/session, or the monitoring state
      machine's own REVOKED status) — see Part 15
      ("Qira must NEVER ... bypass reauthentication" / "grant access")
      and Part 28 ("If Qira fails ... the existing backend security
      engine must remain authoritative").
    - If the AI provider is unavailable entirely, this baseline is
      exactly what gets enforced — never NONE/open-access by default.
"""
from __future__ import annotations

from .schema import QiraContext, RecommendedAction, SEVERITY_TO_STATE, SecurityState, TamperSeverity

# Mirrors monitoring.state.MonitoringThresholds.risk_increase_after —
# at/above this many *consecutive* face failures, a single transient
# anomaly becomes a repeated/suspicious pattern (Part 10, MEDIUM
# examples: "repeated temporary face detection failures").
_REPEATED_FAILURE_THRESHOLD = 2


def compute_baseline(context: QiraContext) -> tuple[TamperSeverity, RecommendedAction, str, tuple[str, ...]]:
    """Returns (severity, action, reason, signals) — the deterministic
    floor. `reason`/`signals` are always populated so the UI/admin can
    see WHY, even when the AI layer is unavailable (Part 16)."""
    signals: list[str] = []

    # Audit-chain integrity is a system-level control, not a per-session
    # authorization-risk score. A historical audit-chain problem must be
    # surfaced separately in the UI, but it must not turn an otherwise
    # healthy live session into Qira=COMPROMISED. Session compromise is
    # reserved for the current device/session/monitoring/risk evidence.
    # This keeps the Qira verdict aligned with the live monitoring state
    # while preserving the audit alert for administrators.
    if context.device_revoked and context.session_revoked:
        signals.append("device_revoked")
        signals.append("session_revoked")
        return (
            TamperSeverity.CRITICAL,
            RecommendedAction.REVOKE,
            "Both the current device and session are already revoked.",
            tuple(signals),
        )

    if context.monitoring_status == "revoked":
        signals.append("monitoring_revoked")
        return (
            TamperSeverity.CRITICAL,
            RecommendedAction.REVOKE,
            "Continuous monitoring already invalidated this authorization "
            "(repeated confirmed identity/liveness failures).",
            tuple(signals),
        )

    if context.device_revoked or context.session_revoked:
        signals.append("device_revoked" if context.device_revoked else "session_revoked")
        return (
            TamperSeverity.HIGH,
            RecommendedAction.REAUTHENTICATE,
            "The current device or session has a confirmed trust failure.",
            tuple(signals),
        )

    # -- HIGH: confirmed identity mismatch or the monitoring state
    # machine already demanding reauthentication. --
    if context.monitoring_status == "reauth_required":
        signals.append("repeated_monitoring_anomalies")
        return (
            TamperSeverity.HIGH,
            RecommendedAction.REAUTHENTICATE,
            "Repeated identity/liveness anomalies triggered the "
            "reauthentication threshold.",
            tuple(signals),
        )

    if context.identity_state == "identity_mismatch":
        signals.append("face_mismatch")
        return (
            TamperSeverity.HIGH,
            RecommendedAction.REAUTHENTICATE,
            "Face verification does not match the enrolled identity.",
            tuple(signals),
        )

    if context.risk_level == "critical":
        signals.append("risk_engine_critical")
        return (
            TamperSeverity.HIGH,
            RecommendedAction.REAUTHENTICATE,
            "Deterministic risk engine reports CRITICAL risk for this session.",
            tuple(signals),
        )

    # -- MEDIUM: repeated-but-unconfirmed anomalies. --
    if context.consecutive_face_failures >= _REPEATED_FAILURE_THRESHOLD:
        signals.append("repeated_face_failures")
        return (
            TamperSeverity.MEDIUM,
            RecommendedAction.MONITOR,
            f"{context.consecutive_face_failures} consecutive face/liveness "
            "checks failed — monitoring sensitivity increased.",
            tuple(signals),
        )

    if context.monitoring_status == "warning" or context.security_posture == "warning":
        signals.append("monitoring_warning")
        return (
            TamperSeverity.MEDIUM,
            RecommendedAction.MONITOR,
            "A transient monitoring anomaly was recorded.",
            tuple(signals),
        )

    if context.risk_level == "high":
        signals.append("risk_engine_high")
        return (
            TamperSeverity.MEDIUM,
            RecommendedAction.MONITOR,
            "Deterministic risk engine reports elevated (HIGH) risk.",
            tuple(signals),
        )

    # -- LOW: nominal. --
    if not context.audit_chain_intact:
        return (
            TamperSeverity.LOW,
            RecommendedAction.NONE,
            "Live session security is nominal. Audit-chain integrity requires separate administrative review.",
            tuple(signals),
        )

    return (
        TamperSeverity.LOW,
        RecommendedAction.NONE,
        "No current security anomalies detected.",
        tuple(signals),
    )


def state_for_severity(severity: TamperSeverity) -> SecurityState:
    return SEVERITY_TO_STATE[severity]

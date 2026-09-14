"""
Orchestrates one Qira assessment cycle end to end:

    1. Build safe context from existing infra (context.py)
    2. Compute the deterministic baseline (policy.py) — the floor
    3. Call the AI provider for an advisory opinion (provider.py) —
       best-effort; any failure falls back to the baseline alone
    4. Merge: severity/action can only move UP from the baseline
    5. Enforce the resulting action through EXISTING repositories
       (device/session revoke, monitoring is left to reauthenticate
       itself through its own already-existing flow)
    6. Audit every step; persist an incident record for CRITICAL

This module is the only place in Qira allowed to call
`device_repo.revoke()` / `session_repo.revoke()` — see Part 20 of the
brief ("The frontend must never be able to simply send revoke=true").
"""
from __future__ import annotations

from datetime import datetime, timezone

from audit.events import AuditEvent
from audit.service import AuditLogService
from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from monitoring.service import MonitoringService

from . import policy
from .context import MonitoringSessionRequired, build_context
from .provider import QiraProviderUnavailable, assess as provider_assess, ask as provider_ask
from .repository import SecurityIncidentRepository
from .schema import (
    QiraAssessment,
    QiraContext,
    QiraDecision,
    RecommendedAction,
    SecurityState,
    TamperSeverity,
    max_action,
    max_severity,
)


class QiraSecurityService:
    def __init__(
        self,
        *,
        monitoring_service: MonitoringService,
        device_repo: DeviceRepository,
        session_repo: SessionRepository,
        audit_service: AuditLogService,
        incident_repo: SecurityIncidentRepository,
    ) -> None:
        self._monitoring = monitoring_service
        self._devices = device_repo
        self._sessions = session_repo
        self._audit = audit_service
        self._incidents = incident_repo

    # ------------------------------------------------------------------
    def get_owner(self, monitoring_session_id: str) -> int | None:
        """Read-only ownership lookup for routers to gate access
        before doing anything else — mirrors
        `MonitoringService.get_owner`."""
        return self._monitoring.get_owner(monitoring_session_id)

    def list_current_snapshots(self):
        return self._monitoring.list_current_snapshots()

    def get_device_status(self, device_id: str):
        return self._devices.get_status(device_id)

    def get_session_status(self, session_id: str):
        return self._sessions.get(session_id)

    def assess_for_session(self, session_id: str, user_role: str) -> QiraDecision:
        record = self._monitoring.get_by_session(session_id)
        if record is None:
            raise MonitoringSessionRequired(f"no active monitoring session for session '{session_id}'")
        return self.assess(monitoring_session_id=record.monitoring_session_id, user_role=user_role)

    # ------------------------------------------------------------------
    def get_context(
        self, *, monitoring_session_id: str, user_role: str, location_permission_state: str | None = None
    ) -> QiraContext:
        return build_context(
            monitoring_session_id=monitoring_session_id,
            monitoring_service=self._monitoring,
            device_repo=self._devices,
            session_repo=self._sessions,
            audit_service=self._audit,
            user_role=user_role,
            location_permission_state=location_permission_state,
        )

    # ------------------------------------------------------------------
    def assess(
        self,
        *,
        monitoring_session_id: str,
        user_role: str,
        location_permission_state: str | None = None,
        now: datetime | None = None,
        enforce: bool = True,
    ) -> QiraDecision:
        now = now or datetime.now(timezone.utc)

        try:
            context = self.get_context(
                monitoring_session_id=monitoring_session_id,
                user_role=user_role,
                location_permission_state=location_permission_state,
            )
        except MonitoringSessionRequired:
            raise

        baseline_severity, baseline_action, baseline_reason, baseline_signals = policy.compute_baseline(context)

        ai_assessment: QiraAssessment | None = None
        ai_available = False
        try:
            ai_assessment = provider_assess(context, baseline_severity.value, baseline_reason)
            ai_available = True
        except QiraProviderUnavailable as exc:
            self._audit.record(
                AuditEvent.QIRA_PROVIDER_UNAVAILABLE,
                "unavailable",
                user_id=context.user_id,
                device_id=context.device_id,
                session_id=context.session_id,
                reason=str(exc)[:300],
                timestamp=now,
            )

        final_severity = baseline_severity
        final_action = baseline_action
        reason = baseline_reason
        signals = list(baseline_signals)
        escalated_by_ai = False

        if ai_assessment is not None:
            merged_severity = max_severity(baseline_severity, ai_assessment.severity)
            merged_action = max_action(baseline_action, ai_assessment.recommended_action)
            # Fail-safe ceiling (Part 15/28): the AI alone can escalate
            # severity up to HIGH/REAUTHENTICATE, but CANNOT be the
            # sole reason access is actually REVOKED — only the
            # deterministic baseline can authorize that (see
            # policy.py module docstring). If the AI pushed for
            # REVOKE but the baseline never reached CRITICAL, cap it
            # at REAUTHENTICATE/HIGH instead of executing a revoke.
            if merged_action is RecommendedAction.REVOKE and baseline_severity is not TamperSeverity.CRITICAL:
                merged_action = RecommendedAction.REAUTHENTICATE
                merged_severity = max_severity(merged_severity, TamperSeverity.HIGH)
                if merged_severity is TamperSeverity.CRITICAL:
                    merged_severity = TamperSeverity.HIGH

            escalated_by_ai = merged_severity != baseline_severity or merged_action != baseline_action
            final_severity, final_action = merged_severity, merged_action
            if escalated_by_ai:
                reason = ai_assessment.reason
                signals = list(dict.fromkeys([*signals, *ai_assessment.signals]))

        security_state = policy.state_for_severity(final_severity)

        # Admin risk-overview calls are explicitly read-only. They may
        # analyze the latest authoritative face/monitoring evidence, but
        # polling an admin table must never revoke or reauthorize a user.
        enforced_action = (
            self._enforce(context=context, action=final_action, now=now)
            if enforce else RecommendedAction.NONE
        )

        incident_id: int | None = None
        if enforce and final_severity is TamperSeverity.CRITICAL and enforced_action is RecommendedAction.REVOKE:
            incident = self._incidents.create(
                user_id=context.user_id,
                device_id=context.device_id,
                session_id=context.session_id,
                monitoring_session_id=context.monitoring_session_id,
                severity=final_severity.value,
                security_state=security_state.value,
                reason=reason,
                signals=tuple(signals),
                action_taken=enforced_action.value,
                qira_assessment=ai_assessment.as_dict() if ai_assessment else None,
                now=now,
            )
            incident_id = incident.incident_id
            self._audit.record(
                AuditEvent.QIRA_ACCESS_REVOKED,
                "revoked",
                user_id=context.user_id,
                device_id=context.device_id,
                session_id=context.session_id,
                risk=final_severity.value,
                reason=reason[:300],
                timestamp=now,
            )
        elif enforce and enforced_action is RecommendedAction.REAUTHENTICATE:
            self._audit.record(
                AuditEvent.QIRA_REAUTH_REQUIRED,
                "reauth_required",
                user_id=context.user_id,
                device_id=context.device_id,
                session_id=context.session_id,
                risk=final_severity.value,
                reason=reason[:300],
                timestamp=now,
            )

        if enforce:
            self._audit.record(
                AuditEvent.QIRA_SECURITY_ASSESSMENT,
                "assessed",
                user_id=context.user_id,
                device_id=context.device_id,
                session_id=context.session_id,
                risk=final_severity.value,
                reason=reason[:300],
                timestamp=now,
            )

        return QiraDecision(
            security_state=security_state,
            severity=final_severity,
            recommended_action=final_action,
            enforced_action=enforced_action,
            reason=reason,
            signals=tuple(signals),
            ai_available=ai_available,
            ai_confidence=ai_assessment.confidence if ai_assessment else None,
            ai_explanation=ai_assessment.reason if ai_assessment else None,
            baseline_severity=baseline_severity,
            escalated_by_ai=escalated_by_ai,
            risk_level=context.risk_level,
            risk_score=round(float(context.risk_score), 2),
            audit_chain_intact=context.audit_chain_intact,
            incident_id=incident_id,
            timestamp=now,
        )

    # ------------------------------------------------------------------
    def ask(
        self, *, monitoring_session_id: str, user_role: str, question: str
    ) -> str:
        """Read-only conversational guidance; never touches enforcement.

        Greetings are handled locally before telemetry collection so a normal
        chat opener can never fail because an optional provider or a transient
        telemetry component is unavailable. Security-specific questions are
        grounded in the current coarse context.
        """
        q = (question or "").strip().lower()
        greetings = {"hi", "hello", "hey", "hii", "helo", "good morning", "good afternoon", "good evening"}
        if q in greetings or any(q.startswith(g + " ") for g in greetings):
            return (
                "Hello! 👋 I'm Qira, your CipherQ Security Copilot. How can I help? "
                "You can check your risk, audit integrity, device trust, monitoring, "
                "or ask what to do next."
            )
        context = self.get_context(monitoring_session_id=monitoring_session_id, user_role=user_role)
        return provider_ask(context, question)

    # ------------------------------------------------------------------
    def _enforce(
        self, *, context: QiraContext, action: RecommendedAction, now: datetime
    ) -> RecommendedAction:
        """Executes the ONE thing Qira is allowed to actually enforce
        through a backend action: REVOKE. REAUTHENTICATE is enforced
        by the existing continuous-monitoring/session machinery
        itself (the monitoring status already reflects
        `reauth_required`, and `POST /api/authorization/sessions/
        {id}/reauthenticate` is the existing recovery path) — Qira
        does not invent a second, competing reauthentication
        mechanism (Part 11: "Do NOT create a fake frontend-only
        reauthentication")."""
        if action is RecommendedAction.REVOKE:
            # Audit-chain compromise is a separate integrity signal. It
            # must not be converted into a live face-monitoring/session
            # revocation by Qira. Existing explicit device/session
            # revocation or monitoring REVOKED state remains authoritative.
            if not context.audit_chain_intact and not (
                context.monitoring_status == "revoked"
                or context.device_revoked
                or context.session_revoked
            ):
                return RecommendedAction.REAUTHENTICATE
            # Qira's continuous-risk enforcement is SESSION-scoped.
            # It must revoke the current authorization session, but it
            # must not permanently poison the underlying device merely
            # because a live session became risky. An explicit
            # administrator device revoke remains the stronger boundary.
            if not context.session_revoked:
                try:
                    self._sessions.revoke(context.session_id)
                except Exception:
                    # Session may already be gone/revoked.
                    pass
            return RecommendedAction.REVOKE
        return action

"""
Builds a `QiraContext` from EXISTING sources only:

    - `monitoring.service.MonitoringService` (read-only `.refresh()`)
      for status/security_state/identity/risk/consecutive failures —
      the same snapshot the topbar badge and dashboard card read.
    - `authorization.devices` / `authorization.sessions` repositories
      for device/session revoked state.
    - `audit.service.AuditLogService` for chain integrity and the
      names (not payloads) of the caller's most recent events.

Nothing here is fabricated, and nothing here calls the AI provider —
this module is pure data collection, matching Part 19 of the brief
("GET /api/security/context ... Qira should use this authoritative
context").
"""
from __future__ import annotations

from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from audit.service import AuditLogService
from monitoring.service import MonitoringService, MonitoringSessionNotFoundError
from monitoring.state import MonitoringSnapshot

from .schema import QiraContext

# How many of the caller's own most-recent audit entries to surface as
# coarse "recent_event_types" context — action names only, never full
# entries/payloads, and capped small so this never becomes a payload
# a prompt-injection-style audit `reason` string could hide inside.
_RECENT_EVENTS_LIMIT = 8


class MonitoringSessionRequired(Exception):
    """Raised when no valid monitoring session is available to build
    context from — Qira has nothing meaningful to analyze without
    one, and must not fabricate a context to fill the gap."""


def build_context(
    *,
    monitoring_session_id: str,
    monitoring_service: MonitoringService,
    device_repo: DeviceRepository,
    session_repo: SessionRepository,
    audit_service: AuditLogService,
    user_role: str,
    location_permission_state: str | None = None,
) -> QiraContext:
    try:
        snapshot: MonitoringSnapshot = monitoring_service.refresh(monitoring_session_id)
    except MonitoringSessionNotFoundError as exc:
        raise MonitoringSessionRequired(str(exc)) from exc

    device_status = device_repo.get_status(snapshot.current_device)
    session_status = session_repo.get(snapshot.current_session)
    session_revoked = session_status is None or getattr(session_status, "revoked", False)

    integrity = audit_service.verify_integrity()

    entries = audit_service.list_entries()
    mine = [e for e in entries if e.user_id == snapshot.current_user]
    recent_event_types = tuple(e.action for e in mine[-_RECENT_EVENTS_LIMIT:][::-1])

    return QiraContext(
        user_id=snapshot.current_user,
        user_role=user_role,
        monitoring_session_id=snapshot.monitoring_session_id,
        device_id=snapshot.current_device,
        session_id=snapshot.current_session,
        monitoring_status=snapshot.status.value,
        # This is the live per-session posture. Audit integrity is passed
        # separately below and must never be flattened into this value.
        security_posture=snapshot.security_state.value,
        identity_state=snapshot.identity_state.value,
        face_present=snapshot.face_present,
        liveness=snapshot.liveness,
        consecutive_face_failures=snapshot.consecutive_face_failures,
        device_revoked=bool(device_status.revoked),
        session_revoked=bool(session_revoked),
        intent_id=snapshot.current_intent,
        intent_lifecycle_state=snapshot.current_lifecycle,
        risk_level=snapshot.current_risk.value,
        risk_score=snapshot.risk_score,
        audit_chain_intact=integrity.valid,
        recent_event_types=recent_event_types,
        location_permission_state=location_permission_state,
    )

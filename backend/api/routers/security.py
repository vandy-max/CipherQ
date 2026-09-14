"""
Qira — CipherQ Security Copilot API.

    GET  /api/security/context           safe current context (Part 19)
    POST /api/security/assess            run one Qira assessment cycle;
                                          backend validates + enforces
                                          (Parts 8-12, 20)
    POST /api/security/ask               read-only grounded Q&A for the
                                          Qira chat widget
    GET  /api/security/incidents         admin: list security incidents
    POST /api/security/incidents/{id}/resolve
                                          admin: authorized recovery
                                          (Part 13)

Every mutating action here goes through `qira.service.QiraSecurityService`,
which is the only code allowed to call device/session `.revoke()` — this
router never accepts a raw "revoke=true" from the client (Part 20).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status

from qira.context import MonitoringSessionRequired
from qira.provider import QiraProviderUnavailable, deterministic_safe_answer
from qira.service import QiraSecurityService

from ..dependencies import (
    get_current_user,
    get_device_repository,
    get_qira_service,
    get_security_incident_repository,
    get_user_repository,
)
from ..rbac import require_owner_or_admin, require_roles
from ..schemas import (
    QiraAskRequest,
    QiraAskResponse,
    QiraAssessRequest,
    QiraDecisionResponse,
    ResolveSecurityIncidentRequest,
    SecurityContextResponse,
    SecurityIncidentResponse,
    UserRiskOverviewResponse,
)

router = APIRouter(prefix="/api/security", tags=["security"])


def _monitoring_session_owner_ok(user, monitoring_session_id: str, service: QiraSecurityService) -> None:
    owner = service.get_owner(monitoring_session_id)
    if owner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitoring session not found")
    require_owner_or_admin(user, owner, action="access")


@router.get("/context", response_model=SecurityContextResponse)
def get_security_context(
    monitoring_session_id: str = Query(...),
    location_permission_state: str | None = Query(None),
    user=Depends(get_current_user),
    service: QiraSecurityService = Depends(get_qira_service),
) -> SecurityContextResponse:
    _monitoring_session_owner_ok(user, monitoring_session_id, service)
    try:
        context = service.get_context(
            monitoring_session_id=monitoring_session_id,
            user_role=user.role,
            location_permission_state=location_permission_state,
        )
    except MonitoringSessionRequired as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return SecurityContextResponse(**context.as_dict())


@router.post("/assess", response_model=QiraDecisionResponse)
def run_assessment(
    payload: QiraAssessRequest,
    user=Depends(get_current_user),
    service: QiraSecurityService = Depends(get_qira_service),
) -> QiraDecisionResponse:
    _monitoring_session_owner_ok(user, payload.monitoring_session_id, service)
    try:
        decision = service.assess(
            monitoring_session_id=payload.monitoring_session_id,
            user_role=user.role,
            location_permission_state=payload.location_permission_state,
        )
    except MonitoringSessionRequired as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return QiraDecisionResponse(**decision.as_dict())


@router.post("/ask", response_model=QiraAskResponse)
def ask_qira(
    payload: QiraAskRequest,
    user=Depends(get_current_user),
    service: QiraSecurityService = Depends(get_qira_service),
) -> QiraAskResponse:
    _monitoring_session_owner_ok(user, payload.monitoring_session_id, service)
    try:
        answer = service.ask(
            monitoring_session_id=payload.monitoring_session_id,
            user_role=user.role,
            question=payload.question,
        )
        return QiraAskResponse(answer=answer, ai_available=True)
    except MonitoringSessionRequired as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    except QiraProviderUnavailable:
        # Compatibility fallback: chat remains useful without any external
        # AI provider and never exposes identifiers/secrets or performs an action.
        context = service.get_context(
            monitoring_session_id=payload.monitoring_session_id,
            user_role=user.role,
        )
        return QiraAskResponse(
            answer=deterministic_safe_answer(context, payload.question),
            ai_available=False,
        )
    except Exception:
        # Chat is an optional, read-only guidance surface. Never expose a raw
        # backend 500 to the user or turn a chat failure into a security action.
        return QiraAskResponse(
            answer=(
                "I’m temporarily unable to read the current security context. "
                "No security action was taken. You can try again, or use the "
                "Quick Checks in Qira when the monitoring context is available."
            ),
            ai_available=False,
        )


# ---------------------------------------------------------------------
# Admin: dynamic risk overview for every registered user
# ---------------------------------------------------------------------

@router.get("/risk-overview", response_model=list[UserRiskOverviewResponse])
def risk_overview(
    user=Depends(require_roles("ADMIN")),
    service: QiraSecurityService = Depends(get_qira_service),
    users=Depends(get_user_repository),
) -> list[UserRiskOverviewResponse]:
    """Read-only authoritative live-monitoring overview for every user.

    This endpoint deliberately does NOT run Qira assessment/enforcement.
    It reads the same monitoring snapshot and last real evidence generated
    by the user's own continuous monitoring heartbeat.
    """
    current = {}
    for snapshot in service.list_current_snapshots():
        existing = current.get(snapshot.current_user)
        if existing is None or snapshot.timestamp > existing.timestamp:
            current[snapshot.current_user] = snapshot

    rows: list[UserRiskOverviewResponse] = []
    for account in users.list_all():
        snapshot = current.get(account.id)
        if snapshot is None:
            rows.append(
                UserRiskOverviewResponse(
                    user_id=account.id,
                    username=account.username,
                    role=account.role,
                    monitoring_status="not_monitored",
                    security_state="NOT_MONITORED",
                    risk_level="unknown",
                    timestamp=datetime.now(timezone.utc),
                )
            )
            continue

        evidence = service.get_latest_evidence(snapshot.monitoring_session_id)
        device_state = service.get_device_status(snapshot.current_device)
        session_state = service.get_session_status(snapshot.current_session)

        rows.append(
            UserRiskOverviewResponse(
                user_id=account.id,
                username=account.username,
                role=account.role,
                monitoring_session_id=snapshot.monitoring_session_id,
                device_id=snapshot.current_device,
                authorization_session_id=snapshot.current_session,
                monitoring_status=snapshot.status.value,
                identity_state=evidence["identity_state"] or snapshot.identity_state.value,
                reason=evidence["reason"] or snapshot.reason or ("; ".join(snapshot.warnings) if snapshot.warnings else None),
                security_state=snapshot.security_state.value,
                risk_level=snapshot.current_risk.value,
                risk_score=snapshot.risk_score,
                qira_security_state=None,
                qira_severity=None,
                qira_recommended_action=None,
                qira_enforced_action=None,
                qira_reason=None,
                face_present=bool(evidence["face_present"]),
                face_match_confidence=evidence["face_match_confidence"],
                liveness=bool(evidence["liveness"]),
                camera_available=bool(evidence["camera_available"]),
                reason_code=evidence["reason_code"],
                consecutive_face_failures=snapshot.consecutive_face_failures,
                device_revoked=bool(device_state.revoked) if device_state else False,
                session_revoked=bool(session_state.revoked) if session_state else True,
                timestamp=snapshot.timestamp,
            )
        )
    return rows


# ---------------------------------------------------------------------
# Admin: security incidents
# ---------------------------------------------------------------------

@router.get("/incidents", response_model=list[SecurityIncidentResponse])
def list_incidents(
    resolved: bool | None = Query(None),
    user=Depends(require_roles("ADMIN")),
    incidents=Depends(get_security_incident_repository),
) -> list[SecurityIncidentResponse]:
    rows = incidents.list_all(resolved=resolved)
    return [SecurityIncidentResponse(**r.as_dict()) for r in rows]


@router.post("/incidents/{incident_id}/resolve", response_model=SecurityIncidentResponse)
def resolve_incident(
    incident_id: int,
    payload: ResolveSecurityIncidentRequest,
    user=Depends(require_roles("ADMIN")),
    incidents=Depends(get_security_incident_repository),
    device_repo=Depends(get_device_repository),
) -> SecurityIncidentResponse:
    # Recovery is explicitly an authorized admin action (Part 13):
    # Qira itself is never allowed to call this. Restoring access here
    # only marks the incident resolved and unrevokes the device it
    # recorded — it never edits audit history and always goes through
    # the SAME device repository every other revoke/unrevoke path in
    # the app uses. The session stays revoked; the user re-establishes
    # a fresh session by logging in again, same as any other revoked-
    # session recovery in this app.
    incident = incidents.get(incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")

    device_repo.unrevoke(incident.device_id)

    resolved = incidents.resolve(incident_id, resolved_by=user.user_id, note=payload.note)
    if resolved is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "incident not found")
    return SecurityIncidentResponse(**resolved.as_dict())

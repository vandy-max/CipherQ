"""
Continuous monitoring API.

    POST /api/monitoring/start      LOGIN -> FACE VERIFIED already happened;
                                     begin watching this session.
    POST /api/monitoring/heartbeat  lightweight polling heartbeat — the
                                     client posts derived face/liveness
                                     telemetry (never raw video), gets
                                     back the current status.
    GET  /api/monitoring/{id}       read-only status refresh (also
                                     catches admin-side device/session
                                     revocations between heartbeats).
    GET  /api/monitoring/{id}/events  the recorded event/audit trail
                                     for this monitoring session.
    POST /api/monitoring/{id}/stop  end monitoring (e.g. on logout).
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status

from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from monitoring.service import MonitoringService, MonitoringSessionNotFoundError
from monitoring.state import MonitoringSnapshot

from ..dependencies import (
    get_current_user,
    get_device_repository,
    get_monitoring_service,
    get_session_repository,
)
from ..rbac import require_owner_or_admin
from ..repositories import MongoDeviceRepository
from ..schemas import (
    MonitoringEventResponse,
    MonitoringHeartbeatRequest,
    MonitoringSnapshotResponse,
    MonitoringStartRequest,
)

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


def _to_response(snapshot: MonitoringSnapshot) -> MonitoringSnapshotResponse:
    return MonitoringSnapshotResponse(
        monitoring_session_id=snapshot.monitoring_session_id,
        current_user=snapshot.current_user,
        current_device=snapshot.current_device,
        current_session=snapshot.current_session,
        status=snapshot.status.value,
        face_present=snapshot.face_present,
        face_match_confidence=snapshot.face_match_confidence,
        liveness=snapshot.liveness,
        current_intent=snapshot.current_intent,
        current_lifecycle=snapshot.current_lifecycle,
        current_risk=snapshot.current_risk.value,
        risk_score=snapshot.risk_score,
        current_authorization_state=snapshot.current_authorization_state,
        authorization_state_hash=snapshot.authorization_state_hash,
        consecutive_face_failures=snapshot.consecutive_face_failures,
        warnings=list(snapshot.warnings),
        expression_hint=snapshot.expression_hint,
        timestamp=snapshot.timestamp,
        security_state=snapshot.security_state.value,
        identity_state=snapshot.identity_state.value,
        reason_code=snapshot.reason_code,
        reason=snapshot.reason,
    )


@router.post("/start", response_model=MonitoringSnapshotResponse)
def start_monitoring(
    payload: MonitoringStartRequest,
    user=Depends(get_current_user),
    service: MonitoringService = Depends(get_monitoring_service),
    sessions: SessionRepository = Depends(get_session_repository),
    devices: DeviceRepository = Depends(get_device_repository),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
) -> MonitoringSnapshotResponse:
    # PART 14 — ownership must be verified BEFORE a monitoring session
    # is created or mutated, not discovered afterward. A user must not
    # be able to start monitoring against another user's device or
    # session, even though `user_id` on the created record is always
    # the caller's own id (see below): without this check, the record
    # itself would be correctly owned while still riding along on a
    # device/session that belongs to someone else, letting monitoring
    # heartbeats leak that other principal's live device/session
    # state. The authenticated caller's session must already exist
    # (i.e. have gone through LOGIN -> FACE VERIFIED -> a real
    # authorized session) and be owned by them; the device, if it has
    # a recorded owner at all, must be that same principal.
    session_state = sessions.get(payload.session_id)
    if session_state is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not authorized to monitor this session")
    require_owner_or_admin(user, session_state.user_id, action="start monitoring for")
    if session_state.device_id != payload.device_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "device_id does not match the authorized session"
        )
    existing_device_owner = device_owners.get_owner(payload.device_id)
    if existing_device_owner is not None:
        require_owner_or_admin(user, existing_device_owner, action="start monitoring for")
    if session_state.revoked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "session is invalid; re-authentication is required before monitoring can start")
    if session_state.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "session is expired; re-authentication is required before monitoring can start")
    device_state = devices.get_status(payload.device_id)
    if device_state.revoked:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "device is revoked; re-authentication is required before monitoring can start")

    # Retire any previous active monitoring record for this exact session
    # before creating the replacement. This makes the backend authoritative
    # even if an old browser heartbeat arrives late.
    previous = service.get_by_session(payload.session_id)
    if previous is not None:
        try:
            service.stop(previous.monitoring_session_id)
        except MonitoringSessionNotFoundError:
            pass

    # user_id is always the authenticated caller's own id — never taken
    # from the request body — so a freshly-started monitoring session
    # is always owned by whoever started it.
    snapshot = service.start(
        user_id=user.user_id,
        device_id=payload.device_id,
        session_id=payload.session_id,
        face_confidence=payload.face_confidence,
        intent_id=payload.intent_id,
    )
    return _to_response(snapshot)


@router.post("/heartbeat", response_model=MonitoringSnapshotResponse)
def heartbeat(
    payload: MonitoringHeartbeatRequest,
    user=Depends(get_current_user),
    service: MonitoringService = Depends(get_monitoring_service),
) -> MonitoringSnapshotResponse:
    # Ownership is checked *before* the heartbeat is processed, not
    # after — otherwise an unauthorized caller could still influence
    # another user's monitoring/risk state (e.g. consecutive-failure
    # counters) via the side effects of `service.heartbeat()` even
    # though the response is ultimately rejected.
    owner = service.get_owner(payload.monitoring_session_id)
    if owner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitoring session not found")
    require_owner_or_admin(user, owner, action="update")
    try:
        snapshot = service.heartbeat(
            monitoring_session_id=payload.monitoring_session_id,
            face_present=payload.face_present,
            face_confidence=payload.face_match_confidence,
            liveness=payload.liveness,
            expression_hint=payload.expression_hint,
            camera_available=payload.camera_available,
        )
    except MonitoringSessionNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _to_response(snapshot)


@router.get("/by-session/{session_id}", response_model=MonitoringSnapshotResponse)
def get_status_by_session(
    session_id: str,
    user=Depends(get_current_user),
    service: MonitoringService = Depends(get_monitoring_service),
) -> MonitoringSnapshotResponse:
    """Return the current non-stopped monitoring session for an authorization session.

    This is a read-only lifecycle-recovery endpoint. It lets an authenticated
    browser reconnect to an already-running monitoring session after a page
    refresh without inventing a new biometric result or requiring a stale
    cached confidence value. Ownership is enforced against the monitoring
    record's user before the snapshot is returned.
    """
    record = service.get_by_session(session_id)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no active monitoring session for this authorization session")
    require_owner_or_admin(user, record.user_id, action="access")
    try:
        snapshot = service.refresh(record.monitoring_session_id)
    except MonitoringSessionNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _to_response(snapshot)


@router.get("/{monitoring_session_id}", response_model=MonitoringSnapshotResponse)
def get_status(
    monitoring_session_id: str,
    user=Depends(get_current_user),
    service: MonitoringService = Depends(get_monitoring_service),
) -> MonitoringSnapshotResponse:
    owner = service.get_owner(monitoring_session_id)
    if owner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitoring session not found")
    require_owner_or_admin(user, owner, action="access")
    try:
        snapshot = service.refresh(monitoring_session_id)
    except MonitoringSessionNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc
    return _to_response(snapshot)


@router.get("/{monitoring_session_id}/events", response_model=list[MonitoringEventResponse])
def get_events(
    monitoring_session_id: str,
    user=Depends(get_current_user),
    service: MonitoringService = Depends(get_monitoring_service),
) -> list[MonitoringEventResponse]:
    # Checked against the session's own recorded owner (not derived
    # from the event list) so an empty-events session still enforces
    # ownership correctly.
    owner = service.get_owner(monitoring_session_id)
    if owner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitoring session not found")
    require_owner_or_admin(user, owner, action="access")
    events = service.list_events(monitoring_session_id)
    return [
        MonitoringEventResponse(event_type=e.event_type, snapshot=_to_response(e.snapshot))
        for e in events
    ]


@router.post(
    "/{monitoring_session_id}/stop",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
def stop_monitoring(
    monitoring_session_id: str,
    user=Depends(get_current_user),
    service: MonitoringService = Depends(get_monitoring_service),
) -> None:
    # Same ownership protection as heartbeat/status/events — stop is
    # not weaker than the other monitoring endpoints.
    owner = service.get_owner(monitoring_session_id)
    if owner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "monitoring session not found")
    require_owner_or_admin(user, owner, action="stop")
    try:
        service.stop(monitoring_session_id)
    except MonitoringSessionNotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc)) from exc

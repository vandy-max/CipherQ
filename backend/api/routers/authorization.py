from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.face_auth import FaceAuthService
from authorization import AuthorizationError, AuthorizationService
from authorization.reauth_requests import ReauthRequestRepository
from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository, SessionRevokedError
from database.session import get_db
from intent.schema import CID

from ..dependencies import (
    get_audit_service,
    get_authorization_service,
    get_current_user,
    get_device_repository,
    get_face_auth_service,
    get_intent_repository,
    get_session_repository,
    get_reauth_request_repository,
)
from ..rbac import is_admin_role, require_owner_or_admin, require_roles
from ..repositories import IntentRepository, MongoDeviceRepository
from ..schemas import (
    AuthorizationStateRequest,
    AuthorizationStateResponse,
    DeviceStatusResponse,
    DeviceTrustResponse,
    ReauthenticateSessionRequest,
    RefreshSessionRequest,
    SessionStatusResponse,
)

router = APIRouter(prefix="/api/authorization", tags=["authorization"])


# ---------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------

@router.get("/devices/{device_id}", response_model=DeviceStatusResponse)
def get_device_status(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
) -> DeviceStatusResponse:
    owner = device_owners.get_owner(device_id)
    require_owner_or_admin(user, owner, action="view")
    status_row = devices.get_status(device_id)
    return DeviceStatusResponse(device_id=status_row.device_id, revoked=status_row.revoked)


@router.get("/devices/{device_id}/trust", response_model=DeviceTrustResponse)
def get_device_trust(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
) -> DeviceTrustResponse:
    """Trusted-device status for THIS device relative to the CALLING
    user (Part 1 of the foundation-security fix pass). No new device
    identity model — this reuses the same ownership binding session
    establishment already relies on (`get_owner`/`claim_owner`) so a
    device can never simultaneously be "trusted" here and "someone
    else's device" for `/sessions/*` — one source of truth.

    Read-only: unlike session establishment, checking trust status
    never claims ownership of an unclaimed device. A caller sees
    "new" until they actually establish a session against it.
    """
    status_row = devices.get_status(device_id)
    owner = device_owners.get_owner(device_id)

    if status_row.revoked:
        trust_status = "revoked"
    elif owner is None:
        trust_status = "new"
    elif owner == user.user_id:
        trust_status = "trusted"
    else:
        trust_status = "foreign"

    return DeviceTrustResponse(
        device_id=device_id,
        status=trust_status,
        revoked=status_row.revoked,
        is_own_device=(owner == user.user_id),
        has_any_owner=(owner is not None),
    )


@router.post(
    "/devices/{device_id}/revoke",
    response_model=DeviceStatusResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def revoke_device(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
    audit: AuditLogService = Depends(get_audit_service),
) -> DeviceStatusResponse:
    """Simulates a device being lost, stolen, or deprovisioned.
    Any subsequent encrypt/decrypt attempt from this device is
    rejected by `AuthorizationService` before any crypto call.
    Administrative operation — ADMIN only,
    regardless of who owns the device (see `require_roles` dependency
    above); a normal user can never revoke a device, including their
    own, through this endpoint."""
    owner = device_owners.get_owner(device_id)
    if owner == user.user_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "an administrator cannot revoke their own device; revoke another user's device instead",
        )
    status_row = devices.revoke(device_id)
    audit.record(
        AuditEvent.DEVICE_REVOKED, "revoked", user_id=user.user_id, device_id=device_id
    )
    return DeviceStatusResponse(device_id=status_row.device_id, revoked=status_row.revoked)


@router.post(
    "/devices/{device_id}/unrevoke",
    response_model=DeviceStatusResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def unrevoke_device(
    device_id: str,
    user=Depends(get_current_user),
    devices: DeviceRepository = Depends(get_device_repository),
    audit: AuditLogService = Depends(get_audit_service),
) -> DeviceStatusResponse:
    status_row = devices.unrevoke(device_id)
    audit.record(
        AuditEvent.DEVICE_UNREVOKED, "unrevoked", user_id=user.user_id, device_id=device_id
    )
    return DeviceStatusResponse(device_id=status_row.device_id, revoked=status_row.revoked)


# ---------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------

@router.get("/sessions/{session_id}", response_model=SessionStatusResponse)
def get_session_status(
    session_id: str,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
) -> SessionStatusResponse:
    session = sessions.get(session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    require_owner_or_admin(user, session.user_id, action="view")
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


@router.post(
    "/sessions/{session_id}/revoke",
    response_model=SessionStatusResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def revoke_session(
    session_id: str,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
    audit: AuditLogService = Depends(get_audit_service),
) -> SessionStatusResponse:
    """Simulates a session being logged out or terminated by an
    administrator. Any subsequent encrypt/decrypt using this session
    is rejected before any crypto call. Administrative operation —
    ADMIN only; a normal user cannot revoke
    even their own session through this endpoint (they simply stop
    using it / let it expire, or an administrator revokes it)."""
    existing = sessions.get(session_id)
    if existing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    if existing.user_id == user.user_id:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "an administrator cannot revoke their own session; revoke another user's session instead",
        )
    try:
        session = sessions.revoke(session_id)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found") from exc
    audit.record(
        AuditEvent.SESSION_REVOKED,
        "revoked",
        user_id=user.user_id,
        session_id=session_id,
        device_id=session.device_id,
    )
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


@router.post("/sessions/{session_id}/refresh", response_model=SessionStatusResponse)
def refresh_session(
    session_id: str,
    payload: RefreshSessionRequest,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
    audit: AuditLogService = Depends(get_audit_service),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
    devices: DeviceRepository = Depends(get_device_repository),
) -> SessionStatusResponse:
    """Establishes a fresh authorized session: un-revokes, extends
    expiry, and bumps the session's `version`. Because `version` is
    folded into the authorization state hash, this immediately
    invalidates any cryptographic session bound to the previous
    version — a fresh derivation is required going forward. If the
    session does not exist yet, it is created (and owned by the
    caller). A normal user may only refresh their own session; an
    admin role may refresh (re-authorize) any user's session."""
    existing = sessions.get(session_id)
    device_status = devices.get_status(payload.device_id) if hasattr(devices, "get_status") else None
    if device_status is not None and device_status.revoked:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "device is revoked; an administrator must restore the device before access can continue",
        )
    if existing is not None:
        require_owner_or_admin(user, existing.user_id, action="refresh")
        try:
            session = sessions.refresh(session_id, ttl=timedelta(minutes=payload.ttl_minutes))
        except SessionRevokedError as exc:
            # CRITICAL: a revoked session must stay revoked through the
            # normal refresh path. Crypto stays blocked; the caller
            # must go through POST /sessions/{id}/reauthenticate
            # (explicit face re-verification) to establish a fresh
            # session.
            audit.record(
                AuditEvent.SESSION_REFRESH_BLOCKED,
                "rejected",
                user_id=user.user_id,
                session_id=session_id,
                device_id=existing.device_id,
                reason="refresh attempted against a revoked session",
            )
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "session is revoked; explicit re-authentication is required",
            ) from exc
    else:
        # A brand-new session must not be established against a device
        # that's already owned by a *different* user — otherwise user
        # B could bind a fresh session to user A's device_id and then
        # operate through it (the core authorization check only looks
        # at `device.revoked`, not who owns it, so an unrevoked device
        # with a mismatched owner would otherwise pass every
        # downstream crypto check). An admin may still do this
        # deliberately (e.g. provisioning a session on a shared/kiosk
        # device on a user's behalf).
        existing_device_owner = device_owners.get_owner(payload.device_id)
        if existing_device_owner is not None:
            require_owner_or_admin(
                user, existing_device_owner, action="establish a session against this device"
            )
        # A brand-new session is always created as owned by the
        # authenticated caller — never by a `user_id` supplied in the
        # request body (there isn't one; `user.user_id` here comes
        # from the JWT).
        session = sessions.get_or_create(
            session_id,
            user_id=user.user_id,
            device_id=payload.device_id,
            ttl=timedelta(minutes=payload.ttl_minutes),
        )

    # The device this session is being established/refreshed against
    # becomes owned by whoever owns the session, the first time it's
    # seen — this is what lets device ownership (section 2) be
    # enforced without requiring a separate device-registration step.
    device_owners.claim_owner(session.device_id, session.user_id)

    audit.record(
        AuditEvent.SESSION_REFRESHED,
        "success",
        user_id=user.user_id,
        session_id=session_id,
        device_id=session.device_id,
    )
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


@router.post("/sessions/{session_id}/reauthenticate", response_model=SessionStatusResponse)
def reauthenticate_session(
    session_id: str,
    payload: ReauthenticateSessionRequest,
    user=Depends(get_current_user),
    sessions: SessionRepository = Depends(get_session_repository),
    devices: DeviceRepository = Depends(get_device_repository),
    audit: AuditLogService = Depends(get_audit_service),
    device_owners: MongoDeviceRepository = Depends(get_device_repository),
    face_auth: FaceAuthService = Depends(get_face_auth_service),
    reauth_requests: ReauthRequestRepository = Depends(get_reauth_request_repository),
) -> SessionStatusResponse:
    """Restores a revoked (or otherwise no-longer-trusted) session —
    but, per policy, only for an ADMIN acting on their own session; see
    the elif block below for why. Unlike `refresh`, this requires a
    live, successful face verification against the caller's OWN
    enrolled identity before anything about the session changes. On
    success it establishes a genuinely fresh session: `revoked`
    cleared, expiry extended, and `version` bumped — the version bump
    is what makes any cryptographic session bound to the previous
    (compromised) version unusable going forward, regardless of
    session_id reuse."""
    existing = sessions.get(session_id)
    target_device_id = existing.device_id if existing is not None else payload.device_id
    device_status = devices.get_status(target_device_id)
    approved_request = None
    if payload.reauth_request_id is not None:
        candidate = reauth_requests.get(payload.reauth_request_id)
        if (
            candidate is not None
            and candidate.status == "approved"
            and candidate.user_id == user.user_id
            and candidate.device_id == target_device_id
            and candidate.session_id == session_id
        ):
            approved_request = candidate
        elif candidate is not None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "the approved reauthorization request does not match this user, device, or session",
            )
        else:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "reauthorization request not found",
            )
    else:
        approved_request = reauth_requests.get_approved_for(
            user.user_id, target_device_id, session_id
        )
    admin_self_service_restore = False

    # A non-admin may cross a revoked device/session boundary only when
    # there is an approved request for this exact user/device/session.
    # An admin may self-service their own target as before.
    if is_admin_role(user.role):
        target_owner = device_owners.get_owner(target_device_id)
        session_owner_ok = existing is None or existing.user_id == user.user_id
        device_owner_ok = target_owner is None or target_owner == user.user_id
        admin_self_service_restore = session_owner_ok and device_owner_ok

    if (device_status.revoked or (existing is not None and existing.revoked)) and not (
        admin_self_service_restore or approved_request is not None
    ):
        if device_status.revoked:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "device is revoked; an administrator must approve an access request before face re-authentication",
            )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "session is revoked; an administrator must approve an access request before face re-authentication",
        )

    if existing is not None:
        require_owner_or_admin(user, existing.user_id, action="re-authenticate")
    else:
        existing_device_owner = device_owners.get_owner(payload.device_id)
        if existing_device_owner is not None:
            require_owner_or_admin(
                user, existing_device_owner, action="establish a session against this device"
            )

    face_result = face_auth.verify(user.user_id, payload.face_descriptor)
    if not face_result.verified:
        audit.record(AuditEvent.FACE_VERIFY_FAILURE, "rejected", user_id=user.user_id, session_id=session_id)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "face verification failed; session remains blocked")
    audit.record(AuditEvent.FACE_VERIFY_SUCCESS, "success", user_id=user.user_id, session_id=session_id)

    # A non-admin approval is a one-time grant for this exact
    # user/device/session. Consume it atomically only after the fresh
    # face verification succeeds and immediately before crossing the
    # revoked security boundary. This prevents an old approval from
    # being reused and keeps approval/reauthentication as one coherent
    # lifecycle.
    if approved_request is not None and not admin_self_service_restore:
        consumed = reauth_requests.consume_approved(
            approved_request.request_id,
            user_id=user.user_id,
            device_id=target_device_id,
            session_id=session_id,
        )
        if consumed is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "the approved reauthorization request has already been consumed; submit a new request",
            )

    if admin_self_service_restore or approved_request is not None:
        # Cross the security boundary only after face verification.
        if device_status.revoked:
            devices.unrevoke(target_device_id)
            audit.record(
                AuditEvent.DEVICE_UNREVOKED,
                "unrevoked",
                user_id=user.user_id,
                device_id=target_device_id,
                reason=(
                    "admin self-service restore via re-authentication (face match confirmed)"
                    if admin_self_service_restore
                    else "approved user re-authentication (face match confirmed)"
                ),
            )

    if existing is not None:
        session = sessions.reauthorize(session_id, ttl=timedelta(minutes=payload.ttl_minutes))
    else:
        session = sessions.get_or_create(
            session_id,
            user_id=user.user_id,
            device_id=payload.device_id,
            ttl=timedelta(minutes=payload.ttl_minutes),
        )

    device_owners.claim_owner(session.device_id, session.user_id)

    audit.record(
        AuditEvent.SESSION_REAUTHENTICATED,
        "success",
        user_id=user.user_id,
        session_id=session_id,
        device_id=session.device_id,
    )
    return SessionStatusResponse(
        session_id=session.session_id,
        device_id=session.device_id,
        revoked=session.revoked,
        expires_at=session.expires_at,
        version=session.version,
    )


# ---------------------------------------------------------------------
# Current authorization/security state (inspection, for the demo)
# ---------------------------------------------------------------------

@router.post("/state", response_model=AuthorizationStateResponse)
def get_authorization_state(
    payload: AuthorizationStateRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    authorization_service: AuthorizationService = Depends(get_authorization_service),
    intent_repo: IntentRepository = Depends(get_intent_repository),
) -> AuthorizationStateResponse:
    """Evaluates and returns the CURRENT authorization/security state
    for a (CID, intent) pair -- the same evaluation `encrypt`/`decrypt`
    perform internally -- without attempting any cryptographic
    operation. Useful for the demo step "show the current
    authorization/security state" and for clients that want to check
    eligibility before assembling an encrypt/decrypt request."""
    try:
        cid = CID(**payload.cid.model_dump())
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    intent_row = intent_repo.get_by_id(payload.intent_id)
    if intent_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "intent not found")
    require_owner_or_admin(user, intent_row.created_by, action="inspect")

    try:
        decision = authorization_service.authorize(
            cid,
            intent_id=intent_row.id,
            intent_lifecycle_state=intent_row.lifecycle_state,
            user_id=user.user_id,
            requesting_user_role=user.role,
        )
    except AuthorizationError as exc:
        return AuthorizationStateResponse(
            authorized=False,
            device_id=cid.device_id,
            session_id=cid.session_id,
            rejection_reason=str(exc),
        )

    return AuthorizationStateResponse(
        authorized=True,
        authorization_state_hash=decision.authorization_state_hash,
        intent_lifecycle_state=decision.security_state.intent_lifecycle_state.value,
        policy_decision_signature=decision.security_state.policy_decision_signature,
        session_version=decision.security_state.session_version,
        device_id=cid.device_id,
        session_id=cid.session_id,
    )

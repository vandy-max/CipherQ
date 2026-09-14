"""
Reauthorization requests — Admin Dashboard "Access Requests" queue.

    POST /api/reauth-requests               user: file a request against
                                              their own revoked device or
                                              session
    GET  /api/reauth-requests/mine           user: their own request history
                                              (used to poll the outcome)
    GET  /api/reauth-requests                admin: list requests (optional
                                              ?status=pending filter)
    POST /api/reauth-requests/{id}/approve   admin: grants a one-time
                                              permission for fresh face
                                              reauthentication
    POST /api/reauth-requests/{id}/reject    admin: leaves the device/session
                                              revoked; records the decision

See authorization/reauth_requests.py for why this exists at all —
in short, a revoked DEVICE or a revoked SESSION belonging to a
non-admin user are both boundaries face re-verification alone cannot
clear, so this is the in-app substitute for a manual admin action.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, status

from authorization.reauth_requests import APPROVED, CONSUMED, PENDING, REJECTED, ReauthRequestRepository

from ..dependencies import (
    get_current_user,
    get_device_repository,
    get_reauth_request_repository,
    get_session_repository,
)
from ..rbac import require_owner_or_admin, require_roles
from ..repositories import MongoDeviceRepository, MongoSessionRepository
from ..schemas import CreateReauthRequestRequest, ReauthRequestResponse, ResolveReauthRequestRequest

router = APIRouter(prefix="/api/reauth-requests", tags=["reauth-requests"])


@router.post("", response_model=ReauthRequestResponse, status_code=status.HTTP_201_CREATED)
def create_reauth_request(
    payload: CreateReauthRequestRequest,
    user=Depends(get_current_user),
    requests: ReauthRequestRepository = Depends(get_reauth_request_repository),
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
) -> ReauthRequestResponse:
    # Ownership check: a user may only request restoration of a device
    # that is actually theirs (or has no recorded owner yet — e.g. it
    # was revoked before any session ever claimed it). Admins may file
    # on behalf of anyone, same convention as every other
    # ownership-scoped endpoint in this app.
    existing_owner = device_repo.get_owner(payload.device_id)
    require_owner_or_admin(user, existing_owner, action="request reauthorization for")

    session = session_repo.get(payload.session_id)
    if session is None or session.user_id != user.user_id or session.device_id != payload.device_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "session does not belong to the requested device/user")

    if requests.has_pending_for(user.user_id, payload.device_id, payload.session_id):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "a reauthorization request for this device is already pending admin review",
        )

    created = requests.create(
        user_id=user.user_id,
        username=user.username,
        device_id=payload.device_id,
        session_id=payload.session_id,
        message=payload.message,
    )
    return ReauthRequestResponse(**created.as_dict())


@router.get("/mine", response_model=list[ReauthRequestResponse])
def list_my_reauth_requests(
    user=Depends(get_current_user),
    requests: ReauthRequestRepository = Depends(get_reauth_request_repository),
) -> list[ReauthRequestResponse]:
    rows = requests.list_for_user(user.user_id)
    return [ReauthRequestResponse(**r.as_dict()) for r in rows]


@router.get("", response_model=list[ReauthRequestResponse])
def list_reauth_requests(
    req_status: str | None = Query(None, alias="status"),
    user=Depends(require_roles("ADMIN")),
    requests: ReauthRequestRepository = Depends(get_reauth_request_repository),
) -> list[ReauthRequestResponse]:
    if req_status is not None and req_status not in (PENDING, APPROVED, REJECTED, CONSUMED):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "status must be pending, approved, rejected, or consumed")
    rows = requests.list_all(status=req_status)
    return [ReauthRequestResponse(**r.as_dict()) for r in rows]


@router.post("/{request_id}/approve", response_model=ReauthRequestResponse)
def approve_reauth_request(
    request_id: int,
    payload: ResolveReauthRequestRequest,
    user=Depends(require_roles("ADMIN")),
    requests: ReauthRequestRepository = Depends(get_reauth_request_repository),
    device_repo: MongoDeviceRepository = Depends(get_device_repository),
    session_repo: MongoSessionRepository = Depends(get_session_repository),
) -> ReauthRequestResponse:
    existing = requests.get(request_id)
    if existing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "reauthorization request not found")
    if existing.status != PENDING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"request is already {existing.status}")

    # Approval is a one-time permission to perform the next fresh face
    # reauthentication.  It deliberately does NOT restore the device or
    # session yet; those security boundaries are crossed only after the
    # user successfully passes face verification on the dedicated
    # reauthentication endpoint.
    resolved = requests.resolve(
        request_id,
        new_status=APPROVED,
        resolved_by=user.user_id,
        resolved_by_username=user.username,
        note=payload.note,
    )
    if resolved is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "request was resolved concurrently")
    return ReauthRequestResponse(**resolved.as_dict())


@router.post("/{request_id}/reject", response_model=ReauthRequestResponse)
def reject_reauth_request(
    request_id: int,
    payload: ResolveReauthRequestRequest,
    user=Depends(require_roles("ADMIN")),
    requests: ReauthRequestRepository = Depends(get_reauth_request_repository),
) -> ReauthRequestResponse:
    # Deliberately does nothing to the device/session — it stays
    # revoked, which is exactly what keeps intent creation, encryption,
    # and decryption blocked for this user (see monitoring/crypto_gate.py
    # and api/routers/intent.py's monitoring gate). Rejecting just
    # records the admin's decision and reason so the user sees an
    # explicit outcome instead of a request that silently never resolves.
    existing = requests.get(request_id)
    if existing is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "reauthorization request not found")
    if existing.status != PENDING:
        raise HTTPException(status.HTTP_409_CONFLICT, f"request is already {existing.status}")

    resolved = requests.resolve(
        request_id,
        new_status=REJECTED,
        resolved_by=user.user_id,
        resolved_by_username=user.username,
        note=payload.note,
    )
    if resolved is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "request was resolved concurrently")
    return ReauthRequestResponse(**resolved.as_dict())

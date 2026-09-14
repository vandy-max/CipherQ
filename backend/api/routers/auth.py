from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.service import AuthenticationService, InvalidCredentialsError, UsernameTakenError

from ..dependencies import get_audit_service, get_auth_service
from ..rbac import DEFAULT_SELF_REGISTER_ROLE, SELF_REGISTERABLE_ROLES
from ..schemas import AuthResponse, LoginRequest, RegisterRequest

router = APIRouter(prefix="/api/auth", tags=["authentication"])


@router.post("/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    service: AuthenticationService = Depends(get_auth_service),
) -> AuthResponse:
    # A self-registered account may choose between the two ordinary user
    # tiers (USER_LEVEL_1 / USER_LEVEL_2) — payload.role already can't be
    # anything else, since the schema's Literal rejects other values, but
    # we re-check against SELF_REGISTERABLE_ROLES here too so this stays
    # safe even if the schema is ever loosened. ADMIN is never reachable
    # through this endpoint: it only comes from the out-of-band seed
    # script or an existing admin's role-management action.
    requested_role = payload.role if payload.role in SELF_REGISTERABLE_ROLES else DEFAULT_SELF_REGISTER_ROLE
    try:
        result = service.register(
            payload.username, payload.email, payload.password, role=requested_role
        )
    except UsernameTakenError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return AuthResponse(
        token=result.token, user_id=result.user_id, username=result.username, role=result.role
    )


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    service: AuthenticationService = Depends(get_auth_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> AuthResponse:
    try:
        result = service.login(payload.username, payload.password)
    except InvalidCredentialsError as exc:
        audit.record(AuditEvent.LOGIN_FAILURE, "rejected", reason=str(exc))
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
    audit.record(AuditEvent.LOGIN_SUCCESS, "success", user_id=result.user_id)
    return AuthResponse(
        token=result.token, user_id=result.user_id, username=result.username, role=result.role
    )

"""
Admin-only user & role management.

Backs the Admin Dashboard's "User & Role Management" section
(requirement item 8). There is no public API that lets a client grant
itself an elevated role — every endpoint here is gated to ADMIN only,
server-side, via `require_roles`, exactly like `api/routers/policies.py`.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pymongo.database import Database

from audit.events import AuditEvent
from audit.service import AuditLogService
from database.session import get_db

from ..dependencies import get_audit_service, get_current_user
from ..rbac import ROLE_DEFAULT_PRIVILEGE, require_roles
from ..repositories import MongoUserRepository
from ..schemas import UpdateUserRoleRequest, UserResponse

router = APIRouter(prefix="/api/users", tags=["users"])


def _to_response(record) -> UserResponse:
    return UserResponse(id=record.id, username=record.username, email=record.email, role=record.role)


@router.get("", response_model=list[UserResponse], dependencies=[Depends(require_roles("ADMIN"))])
def list_users(db: Database = Depends(get_db)) -> list[UserResponse]:
    return [_to_response(u) for u in MongoUserRepository(db).list_all()]


@router.put(
    "/{user_id}/role",
    response_model=UserResponse,
    dependencies=[Depends(require_roles("ADMIN"))],
)
def update_user_role(
    user_id: int,
    payload: UpdateUserRoleRequest,
    db: Database = Depends(get_db),
    user=Depends(get_current_user),
    audit: AuditLogService = Depends(get_audit_service),
) -> UserResponse:
    if payload.role not in ROLE_DEFAULT_PRIVILEGE:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"unknown role '{payload.role}'; must be one of {sorted(ROLE_DEFAULT_PRIVILEGE)}",
        )
    repo = MongoUserRepository(db)
    target = repo.get_by_id(user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")

    updated = repo.update_role(user_id, payload.role)
    audit.record(
        AuditEvent.ROLE_CHANGED,
        "success",
        user_id=user.user_id,
        reason=f"user {user_id} ({target.username}) role '{target.role}' -> '{payload.role}'",
    )
    return _to_response(updated)

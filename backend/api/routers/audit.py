from __future__ import annotations

from fastapi import APIRouter, Depends

from audit.service import AuditLogService

from ..dependencies import get_audit_service, get_current_user
from ..rbac import require_roles
from ..schemas import AuditLogEntryResponse, AuditVerifyResponse

router = APIRouter(prefix="/api/audit", tags=["audit"])

# The audit trail spans every user's activity by design (that's the
# point of a tamper-evident audit log) — so unlike the resource-scoped
# ownership checks elsewhere, access here is role-gated rather than
# per-user: any employee, on their own, is not supposed to be able to
# browse everyone else's device/session/intent activity.
_AUDIT_READ_ROLES = ("ADMIN", "USER_LEVEL_2")


@router.get("/logs", response_model=list[AuditLogEntryResponse])
def list_logs(
    service: AuditLogService = Depends(get_audit_service),
    _user=Depends(require_roles(*_AUDIT_READ_ROLES)),
) -> list[AuditLogEntryResponse]:
    entries = service.list_entries()
    return [
        AuditLogEntryResponse(
            timestamp=entry.timestamp,
            user_id=entry.user_id,
            action=entry.action,
            intent_hash=entry.intent_hash,
            result=entry.result,
            current_log_hash=entry.current_log_hash,
            session_id=entry.session_id,
            device_id=entry.device_id,
            resource=entry.resource,
            operation=entry.operation,
            risk=entry.risk,
            reason=entry.reason,
        )
        for entry in entries
    ]


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_chain(
    service: AuditLogService = Depends(get_audit_service),
    _user=Depends(require_roles(*_AUDIT_READ_ROLES)),
) -> AuditVerifyResponse:
    result = service.verify_integrity()
    # PHASE 4: a broken hash chain is a system-wide integrity failure —
    # "COMPROMISED" — distinct from any single session's REVOKED state.
    return AuditVerifyResponse(
        valid=result.valid,
        first_invalid_index=result.first_invalid_index,
        reason=result.reason,
        security_state="compromised" if not result.valid else "normal",
        checks=result.checks,
        checked_entries=result.checked_entries,
    )

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from audit.events import AuditEvent
from audit.service import AuditLogService
from authentication.face_auth import FaceAuthService

from ..dependencies import get_audit_service, get_current_user, get_face_auth_service
from ..schemas import FaceEnrollRequest, FaceStatusResponse, FaceVerifyRequest, FaceVerifyResponse

router = APIRouter(prefix="/api/face", tags=["face-auth"])


from fastapi import Response, status


@router.get("/status", response_model=FaceStatusResponse)
def status_check(
    service: FaceAuthService = Depends(get_face_auth_service),
    user=Depends(get_current_user),
) -> FaceStatusResponse:
    """Enrollment status only — never returns the descriptor itself."""
    return FaceStatusResponse(enrolled=service.is_enrolled(user.user_id))


@router.post(
    "/enroll",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    response_model=None,
)
def enroll(
    payload: FaceEnrollRequest,
    service: FaceAuthService = Depends(get_face_auth_service),
    user=Depends(get_current_user),
) -> None:
    try:
        service.enroll(user.user_id, payload.descriptor)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc


@router.post("/verify", response_model=FaceVerifyResponse)
def verify(
    payload: FaceVerifyRequest,
    service: FaceAuthService = Depends(get_face_auth_service),
    user=Depends(get_current_user),
    audit: AuditLogService = Depends(get_audit_service),
) -> FaceVerifyResponse:
    try:
        result = service.verify(user.user_id, payload.descriptor)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    if result.verified:
        audit.record(AuditEvent.FACE_VERIFY_SUCCESS, "success", user_id=user.user_id)
    else:
        audit.record(AuditEvent.FACE_VERIFY_FAILURE, "rejected", user_id=user.user_id)
    return FaceVerifyResponse(
        verified=result.verified, confidence=result.confidence, distance=result.distance
    )

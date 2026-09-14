from __future__ import annotations

from fastapi import APIRouter, Depends

from audit.events import AuditEvent
from audit.service import AuditLogService
from policy.geofence import LocationGeofenceService

from ..dependencies import get_audit_service, get_current_user, get_geofence_service
from ..schemas import (
    CheckLocationRequest,
    EnrollTrustedLocationRequest,
    LocationCheckResponse,
    TrustedLocationResponse,
)

router = APIRouter(prefix="/api/location", tags=["location"])


@router.post("/trust", response_model=TrustedLocationResponse)
def enroll_trusted_location(
    payload: EnrollTrustedLocationRequest,
    user=Depends(get_current_user),
    geofence: LocationGeofenceService = Depends(get_geofence_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> TrustedLocationResponse:
    """Establishes (or re-establishes) the caller's single trusted
    location, from a browser Geolocation reading the FRONTEND already
    obtained explicit permission for — this endpoint never itself
    requests or bypasses that permission. Overwrites any previous
    value; no location history is ever stored (Part 2 requirement)."""
    location = geofence.enroll(
        user.user_id, payload.latitude, payload.longitude, payload.accuracy_m
    )
    audit.record(
        AuditEvent.LOCATION_TRUSTED_ESTABLISHED,
        "success",
        user_id=user.user_id,
        reason=f"accuracy_m={payload.accuracy_m}",
    )
    return TrustedLocationResponse(
        established=True,
        latitude=location.latitude,
        longitude=location.longitude,
        accuracy_m=location.accuracy_m,
        established_at=location.established_at,
    )


@router.get("/trust", response_model=TrustedLocationResponse)
def get_trusted_location(
    user=Depends(get_current_user),
    geofence: LocationGeofenceService = Depends(get_geofence_service),
) -> TrustedLocationResponse:
    location = geofence.get(user.user_id)
    if location is None:
        return TrustedLocationResponse(established=False)
    return TrustedLocationResponse(
        established=True,
        latitude=location.latitude,
        longitude=location.longitude,
        accuracy_m=location.accuracy_m,
        established_at=location.established_at,
    )


@router.delete("/trust", response_model=TrustedLocationResponse)
def clear_trusted_location(
    user=Depends(get_current_user),
    geofence: LocationGeofenceService = Depends(get_geofence_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> TrustedLocationResponse:
    geofence.clear(user.user_id)
    audit.record(AuditEvent.LOCATION_TRUSTED_CLEARED, "success", user_id=user.user_id)
    return TrustedLocationResponse(established=False)


@router.post("/check", response_model=LocationCheckResponse)
def check_location(
    payload: CheckLocationRequest,
    user=Depends(get_current_user),
    geofence: LocationGeofenceService = Depends(get_geofence_service),
    audit: AuditLogService = Depends(get_audit_service),
) -> LocationCheckResponse:
    """Compares a current (permitted) reading against the caller's
    trusted location and reports whether they're inside the
    configured radius. A missing lat/lon (permission denied/
    unavailable) is reported as "unknown" — explicitly NOT treated as
    a violation or as malicious (Part 3 requirement). This endpoint is
    informational/advisory: it does not itself block anything — the
    frontend uses the result to decide whether to proceed with a
    protected operation (see fix-pass report for why server-side
    enforcement is deliberately out of scope this pass)."""
    result = geofence.check(
        user.user_id,
        payload.latitude,
        payload.longitude,
        payload.accuracy_m,
        radius_m=payload.radius_m,
    )
    audit.record(
        AuditEvent.LOCATION_CHECKED,
        result.status,
        user_id=user.user_id,
        reason=f"distance_m={result.distance_m} radius_m={result.radius_m}",
    )
    return LocationCheckResponse(
        status=result.status,
        distance_m=result.distance_m,
        radius_m=result.radius_m,
        trusted_location_established=result.trusted_location_established,
    )

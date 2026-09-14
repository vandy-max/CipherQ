"""
Trusted Location / Geofence — Parts 2 and 3 of the foundation-security
fix pass.

Deliberately self-contained and NOT wired into `/api/encrypt` or
`/api/decrypt` authorization in this pass: those flows are already
covered by device/session/lifecycle/policy/risk checks with existing
test coverage, and this fix pass's own instructions are explicit about
minimizing blast radius ("do not rebuild", "do not change crypto
logic"). This module gives the frontend everything it needs to
display trusted-location state and enforce the block CLIENT-side
before even attempting a protected operation (Part 3's "BLOCK
PROTECTED OPERATION" flow), while leaving server-side enrollment of
this as a mandatory policy gate as a follow-up, deliberately scoped
out — see the fix-pass final report for why.

DO NOT store location history — only ONE trusted point per user, ever
overwritten by re-enrollment, never appended to.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

# Configurable, not hard-coded to one arbitrary number (Part 3
# requirement). Overridable per deployment via
# `LocationGeofenceService(default_radius_m=...)`.
DEFAULT_TRUSTED_RADIUS_M = 250.0

# Earth's mean radius in meters, for the haversine distance below.
_EARTH_RADIUS_M = 6371000.0


@dataclass(frozen=True)
class TrustedLocation:
    user_id: int
    latitude: float
    longitude: float
    accuracy_m: float | None
    established_at: datetime


class TrustedLocationRepository(Protocol):
    def get(self, user_id: int) -> TrustedLocation | None: ...
    def set(self, location: TrustedLocation) -> TrustedLocation: ...
    def clear(self, user_id: int) -> None: ...


class InMemoryTrustedLocationRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._locations: dict[int, TrustedLocation] = {}

    def get(self, user_id: int) -> TrustedLocation | None:
        return self._locations.get(user_id)

    def set(self, location: TrustedLocation) -> TrustedLocation:
        self._locations[location.user_id] = location
        return location

    def clear(self, user_id: int) -> None:
        self._locations.pop(user_id, None)


def haversine_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance between two lat/lon points, in meters."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * _EARTH_RADIUS_M * math.asin(min(1.0, math.sqrt(a)))


@dataclass(frozen=True)
class GeofenceResult:
    status: str  # "trusted" | "outside_trusted_zone" | "unknown" | "not_enrolled"
    distance_m: float | None
    radius_m: float
    trusted_location_established: bool


class LocationGeofenceService:
    def __init__(
        self,
        repository: TrustedLocationRepository,
        default_radius_m: float = DEFAULT_TRUSTED_RADIUS_M,
    ) -> None:
        self._repo = repository
        self._default_radius_m = default_radius_m

    def enroll(
        self, user_id: int, latitude: float, longitude: float, accuracy_m: float | None
    ) -> TrustedLocation:
        """Establishes (or re-establishes) the user's single trusted
        location. Overwrites any previous value — no history kept."""
        location = TrustedLocation(
            user_id=user_id,
            latitude=latitude,
            longitude=longitude,
            accuracy_m=accuracy_m,
            established_at=datetime.now(timezone.utc),
        )
        return self._repo.set(location)

    def get(self, user_id: int) -> TrustedLocation | None:
        return self._repo.get(user_id)

    def clear(self, user_id: int) -> None:
        self._repo.clear(user_id)

    def check(
        self,
        user_id: int,
        current_latitude: float | None,
        current_longitude: float | None,
        current_accuracy_m: float | None,
        radius_m: float | None = None,
    ) -> GeofenceResult:
        """`current_latitude`/`current_longitude` of `None` means the
        browser did not supply a location (permission denied or
        unavailable) — this is reported as "unknown", explicitly NOT
        treated as a violation or as malicious (Part 3 requirement)."""
        effective_radius = radius_m if radius_m is not None else self._default_radius_m
        trusted = self._repo.get(user_id)

        if trusted is None:
            return GeofenceResult(
                status="not_enrolled",
                distance_m=None,
                radius_m=effective_radius,
                trusted_location_established=False,
            )

        if current_latitude is None or current_longitude is None:
            return GeofenceResult(
                status="unknown",
                distance_m=None,
                radius_m=effective_radius,
                trusted_location_established=True,
            )

        distance = haversine_distance_m(
            trusted.latitude, trusted.longitude, current_latitude, current_longitude
        )
        # GPS accuracy is given the benefit of the doubt: a request
        # measured as just outside the radius but within its own
        # accuracy margin is not treated as a violation.
        accuracy_allowance = current_accuracy_m or 0.0
        inside = distance <= (effective_radius + accuracy_allowance)

        return GeofenceResult(
            status="trusted" if inside else "outside_trusted_zone",
            distance_m=distance,
            radius_m=effective_radius,
            trusted_location_established=True,
        )

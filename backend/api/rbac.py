"""
Centralized RBAC role definitions and helpers.

This is the single source of truth for the platform's role model and
privilege levels — every router that needs a role check imports from
here instead of hardcoding role strings or duplicating checks.

`Authenticated != Authorized`: having a valid JWT (see
`api/dependencies.py::get_current_user`) only proves *who* the caller
is. Whether that identity is allowed to perform a given operation is
decided here (role-based) and, for resource-scoped operations, by an
ownership check performed separately in the resource's own router
(see e.g. `api/routers/decryption.py`) since ownership always requires
loading the specific resource first.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, status

from .dependencies import get_current_user

# ---------------------------------------------------------------------
# Roles & privilege levels
# ---------------------------------------------------------------------

ADMIN = "ADMIN"
USER_LEVEL_2 = "USER_LEVEL_2"
USER_LEVEL_1 = "USER_LEVEL_1"

# Domain-neutral role model: three tiers describing a generic
# internal-security / privileged-access platform, not specific to
# banking. A deployment maps its own titles (bank teller, clinician,
# case officer, analyst, etc.) onto these roles via configuration/data
# — never by hardcoding industry vocabulary here.
#
# Do not change these role names or privilege levels without updating
# every place that reasons about relative privilege.
ROLE_DEFAULT_PRIVILEGE: dict[str, int] = {
    USER_LEVEL_1: 1,
    USER_LEVEL_2: 2,
    ADMIN: 3,
}

# The least-privileged role assigned to a self-registered account when
# the request doesn't specify one.
DEFAULT_SELF_REGISTER_ROLE = USER_LEVEL_1

# Roles a client is allowed to request for itself at `/api/auth/register`.
# Deliberately excludes ADMIN: admin is never self-service. The only two
# ways to get an ADMIN account are scripts/seed_admin.py (out-of-band,
# fixed/confidential bootstrap credentials — see that script's docstring)
# or an existing admin promoting someone via `PUT /api/users/{id}/role`.
# The two ordinary tiers, by contrast, are exactly what a normal signup
# — including any demo/test user — is free to choose between; nothing
# about them is confidential or admin-gated.
SELF_REGISTERABLE_ROLES = frozenset({USER_LEVEL_1, USER_LEVEL_2})

# Roles allowed to perform security/administrative operations on
# resources they do not own: revoke/unrevoke a device or session that
# belongs to another user, manage policies, and — per the "admin can
# operate on another user's device/session/etc for an explicitly
# administrative operation" requirement — bypass ownership checks
# elsewhere in the app.
ADMIN_ROLES = frozenset({ADMIN})

# Same membership as ADMIN_ROLES today (there is only one admin tier
# now), kept as a distinct name so a future narrower gate doesn't have
# to be invented from scratch.
SUPER_ADMIN_ROLES = frozenset({ADMIN})


def is_admin_role(role: str) -> bool:
    return role in ADMIN_ROLES


def require_roles(*roles: str):
    """FastAPI dependency factory: `Depends(require_roles("SYSTEM_ADMIN"))`.

    Returns the authenticated `TokenPayload` (like `get_current_user`)
    if the caller's role is one of `roles`; otherwise raises 403. Use
    this for endpoints where the entire operation is role-gated
    regardless of which specific resource is targeted (e.g. policy
    writes). For ownership-scoped endpoints (a specific device,
    session, intent, or encryption record), fetch the resource first
    and check ownership explicitly — see `require_owner_or_admin`
    below — since that can only happen after the resource is loaded.
    """
    allowed = frozenset(roles)

    def _dependency(user=Depends(get_current_user)):
        if user.role not in allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"this operation requires one of the following roles: {sorted(allowed)}",
            )
        return user

    return _dependency


def require_owner_or_admin(user, owner_user_id: int | None, *, action: str = "access") -> None:
    """Raise 403 unless `user` owns the resource (its recorded
    `owner_user_id` matches `user.user_id`) or holds an admin role.

    `owner_user_id` of `None` means the resource has no recorded owner
    yet (e.g. a device nobody has ever established a session for) — in
    that case only an admin may act on it, since there is no owner to
    match against and a normal user has no verifiable claim to it.

    Deliberately generic ("access denied") rather than naming who the
    actual owner is, so this never leaks another user's identity or
    confirms that a given ID belongs to somebody else.
    """
    if is_admin_role(user.role):
        return
    if owner_user_id is not None and owner_user_id == user.user_id:
        return
    raise HTTPException(status.HTTP_403_FORBIDDEN, f"not authorized to {action} this resource")

"""
Canonical audit event names — PHASE 4 "AUDIT" requirement.

These are the exact `action` strings CipherQ commits to writing to the
tamper-evident audit chain (`audit.service.AuditLogService.record`)
somewhere in the system, so that audit coverage for the full
authentication -> intent -> crypto -> monitoring -> revocation
lifecycle can be verified by grep-ing this one list rather than
hunting through every call site.

`AuditLogService.record()` still accepts any string `action` (nothing
in the hash chain enforces this vocabulary) — this module exists for
consistency and testability, not as a runtime constraint.
"""
from __future__ import annotations


class AuditEvent:
    # -- Authentication --
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    FACE_VERIFY_SUCCESS = "FACE_VERIFY_SUCCESS"
    FACE_VERIFY_FAILURE = "FACE_VERIFY_FAILURE"

    # -- Intent lifecycle --
    INTENT_CREATED = "INTENT_CREATED"
    INTENT_VALIDATED = "INTENT_VALIDATED"
    INTENT_APPROVED = "INTENT_APPROVED"
    INTENT_REJECTED = "INTENT_REJECTED"
    INTENT_USED = "INTENT_USED"
    INTENT_EXPIRED = "INTENT_EXPIRED"
    INTENT_ARCHIVED = "INTENT_ARCHIVED"
    INTENT_DESTROYED = "INTENT_DESTROYED"

    # -- Crypto --
    ENCRYPT_SUCCESS = "ENCRYPT_SUCCESS"
    ENCRYPT_REJECTED = "ENCRYPT_REJECTED"
    ENCRYPT_FAILURE = "ENCRYPT_FAILURE"
    DECRYPT_SUCCESS = "DECRYPT_SUCCESS"
    DECRYPT_REJECTED = "DECRYPT_REJECTED"

    # -- Policy / risk gates --
    POLICY_DENIED = "POLICY_DENIED"
    RISK_DENIED = "RISK_DENIED"

    # -- Revocation / session lifecycle --
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DEVICE_UNREVOKED = "DEVICE_UNREVOKED"
    SESSION_REVOKED = "SESSION_REVOKED"
    SESSION_REFRESHED = "SESSION_REFRESHED"
    SESSION_REFRESH_BLOCKED = "SESSION_REFRESH_BLOCKED"
    SESSION_REAUTH_REQUIRED = "SESSION_REAUTH_REQUIRED"
    SESSION_REAUTHENTICATED = "SESSION_REAUTHENTICATED"

    # -- Administration --
    ROLE_CHANGED = "ROLE_CHANGED"

    # -- Continuous monitoring --
    MONITORING_STARTED = "MONITORING_STARTED"
    MONITORING_WARNING = "MONITORING_WARNING"
    MONITORING_REAUTH_REQUIRED = "MONITORING_REAUTH_REQUIRED"
    MONITORING_REVOKED = "MONITORING_REVOKED"
    MONITORING_TERMINATED = "MONITORING_TERMINATED"

    # -- Audit integrity --
    AUDIT_TAMPER_DETECTED = "AUDIT_TAMPER_DETECTED"

    # -- Trusted location / geofence (Part 2/3, foundation-security
    # fix pass) --
    LOCATION_TRUSTED_ESTABLISHED = "LOCATION_TRUSTED_ESTABLISHED"
    LOCATION_TRUSTED_CLEARED = "LOCATION_TRUSTED_CLEARED"
    LOCATION_CHECKED = "LOCATION_CHECKED"

    # -- Qira Security Copilot --
    QIRA_SECURITY_ASSESSMENT = "QIRA_SECURITY_ASSESSMENT"
    QIRA_REAUTH_REQUIRED = "QIRA_REAUTH_REQUIRED"
    QIRA_ACCESS_REVOKED = "QIRA_ACCESS_REVOKED"
    QIRA_INCIDENT_RESOLVED = "QIRA_INCIDENT_RESOLVED"
    QIRA_PROVIDER_UNAVAILABLE = "QIRA_PROVIDER_UNAVAILABLE"


ALL_EVENTS: frozenset[str] = frozenset(
    value
    for name, value in vars(AuditEvent).items()
    if not name.startswith("_") and isinstance(value, str)
)

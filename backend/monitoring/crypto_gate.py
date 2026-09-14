"""Authoritative monitoring gate for protected cryptographic operations.

Crypto is allowed while continuous monitoring is ACTIVE or WARNING.
Crypto is blocked when monitoring requires reauthentication or is REVOKED.
Qira is advisory here; it must not replace the live monitoring state machine.
"""
from __future__ import annotations

from monitoring.state import MonitoringStatus


class MonitoringCryptoBlockedError(Exception):
    def __init__(self, status: MonitoringStatus | None, reason: str):
        self.status = status
        self.reason = reason
        super().__init__(reason)


def require_crypto_monitoring(monitoring_service, *, session_id: str, user_id: int):
    """Return the current monitoring snapshot or fail closed.

    ACTIVE and WARNING are usable states. REAUTH_REQUIRED and REVOKED are
    deliberately blocked until a fresh authorized session is established.
    The monitoring record must belong to the authenticated user.
    """
    record = monitoring_service.get_by_session(session_id)
    if record is None or record.stopped:
        raise MonitoringCryptoBlockedError(
            None,
            "continuous monitoring is not active for this session; session is removed or monitoring is not established",
        )
    if record.user_id != user_id:
        raise MonitoringCryptoBlockedError(None, "monitoring session does not belong to the authenticated user")

    snapshot = monitoring_service.refresh(record.monitoring_session_id)
    if snapshot.status is MonitoringStatus.REAUTH_REQUIRED:
        raise MonitoringCryptoBlockedError(
            snapshot.status,
            "cryptographic access is blocked until fresh reauthentication succeeds",
        )
    if snapshot.status is MonitoringStatus.REVOKED:
        raise MonitoringCryptoBlockedError(
            snapshot.status,
            "session is revoked; cryptographic access is blocked until a fresh authorized session is established",
        )

    # ACTIVE and WARNING intentionally remain usable. Monitoring itself
    # continues in both states and the next heartbeat can still escalate
    # to REAUTH_REQUIRED or REVOKED.
    return snapshot

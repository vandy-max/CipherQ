"""
SecurityContextCollector — turns "a request just came in" into a fully
populated `policy.risk.RiskFactors` object, automatically, from signals
that already exist elsewhere in CipherQ.

Why this exists
----------------
Before this module, `/api/encrypt` and `/api/decrypt` each built their
own `RiskFactors(face_confidence=face_confidence)` by hand — every
other field (`device_changed`, `sensitive_resource_access`,
`repeated_denied_requests`, `revoked_device_or_session`, ...) silently
defaulted to "nothing unusual", regardless of what was actually true.
The risk gate was real, but the context feeding it was not.

This module is the single place that assembles that context. It never
invents data: every signal it reports is derived from a request that
already carries it (the CID) or from state another subsystem already
owns and persists:

    device / session validity  -> authorization.devices / .sessions
                                   (the SAME repositories
                                   AuthorizationService checks)
    prior activity for this
    user (denied requests,
    face failures, failed
    logins, device/resource
    history)                   -> audit.service.AuditLogService
                                   (the SAME tamper-evident log
                                   everything else writes to)
    resource/operation
    sensitivity                -> the CID itself (`classification`
                                   field) plus a small, explicit,
                                   configurable sensitive-keyword list
                                   — never inferred from nothing

Nothing here is authoritative. The output is a `RiskFactors` value
that callers still hand to `policy.risk.RiskEngine` (deterministic,
threshold-based, and what actually gates the request) and,
advisorily, to `policy.ml_risk.MLRiskModel`. This module only makes
sure both of those receive real, current signals instead of an
all-defaults, mostly-blind view of the request.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Protocol

from audit.events import AuditEvent
from audit.hash_chain import AuditEntry
from authorization.devices import DeviceRepository
from authorization.sessions import SessionRepository
from intent.schema import CID

from .risk import RiskFactors

# How far back "repeated"/"recent" signals look. Kept short and
# request-scoped on purpose: this is meant to catch a burst of
# suspicious activity around *this* request, not build a long-term
# behavioral profile (which would need real storage/retention design
# this project does not have).
DEFAULT_LOOKBACK = timedelta(minutes=15)

# How far back into the audit log this module is willing to scan when
# looking for "has this user ever used this device/resource before".
# Bounded so a large production audit log can't turn every encrypt/
# decrypt call into an unbounded full-table scan.
_MAX_HISTORY_SCAN = 2000

_DENIED_ACTIONS = frozenset(
    {
        AuditEvent.ENCRYPT_REJECTED,
        AuditEvent.DECRYPT_REJECTED,
        AuditEvent.POLICY_DENIED,
        AuditEvent.RISK_DENIED,
    }
)

# Explicit, reviewable list — not a guess. A resource is treated as
# sensitive if its `classification` (a real CID field) matches one of
# these, OR its resource path contains one of these keywords. Either
# list is intentionally small and can be extended via the
# `sensitive_classifications` / `sensitive_keywords` constructor args
# without touching this module.
_DEFAULT_SENSITIVE_CLASSIFICATIONS = frozenset(
    {"confidential", "secret", "restricted", "top-secret", "classified"}
)
_DEFAULT_SENSITIVE_KEYWORDS = ("secret", "confidential", "finance", "payroll", "admin", "prod")


class AuditHistorySource(Protocol):
    """Matches `audit.service.AuditLogService`'s public read API — this
    module depends on the service, not the underlying repository, so
    it works the same whether the audit log is Mongo-backed or the
    in-memory test double."""

    def list_entries(self) -> Iterable[AuditEntry]: ...


@dataclass(frozen=True)
class CollectedContext:
    """`RiskFactors` plus the raw counts/flags that produced it, kept
    around for audit logging and the structured "signals_analyzed" /
    "detected_patterns" output the AI risk endpoint surfaces —
    `RiskFactors` alone can't be told apart from "nothing happened"
    after the fact."""

    factors: RiskFactors
    signals_analyzed: tuple[str, ...]
    detected_patterns: tuple[str, ...]


class SecurityContextCollector:
    def __init__(
        self,
        device_repository: DeviceRepository,
        session_repository: SessionRepository,
        audit_source: AuditHistorySource,
        sensitive_classifications: frozenset[str] = _DEFAULT_SENSITIVE_CLASSIFICATIONS,
        sensitive_keywords: tuple[str, ...] = _DEFAULT_SENSITIVE_KEYWORDS,
        lookback: timedelta = DEFAULT_LOOKBACK,
    ) -> None:
        self._devices = device_repository
        self._sessions = session_repository
        self._audit_source = audit_source
        self._sensitive_classifications = sensitive_classifications
        self._sensitive_keywords = sensitive_keywords
        self._lookback = lookback

    def collect(
        self,
        user_id: int,
        cid: CID,
        face_confidence: float | None,
        now: datetime | None = None,
        fold_device_session_revocation_into_score: bool = True,
    ) -> CollectedContext:
        """`fold_device_session_revocation_into_score=False` is for
        callers (encrypt/decrypt routers) where `AuthorizationService`
        immediately follows this call and is the authoritative,
        already-tested gate for device/session revocation — it raises
        `DeviceRevokedError`/`SessionInvalidError` with the exact
        status codes and audit events those flows already commit to.
        Double-gating the SAME fact through the risk engine as well
        would just replace that specific, well-typed rejection with a
        generic 403 "high risk assessment", which is a real API/audit
        contract change this fix pass must not make. The signal is
        still computed (so monitoring, which owns this decision
        elsewhere, and detected-pattern reporting still see it) — it's
        only excluded from the *scored* factors in that one case.
        """
        now = now or datetime.now(timezone.utc)
        window_start = now - self._lookback

        # -- Device / session validity: reuse exactly what
        # AuthorizationService is about to check, so this signal is
        # never out of sync with what actually gates the request. --
        device_status = self._devices.get_status(cid.device_id)
        session_state = self._sessions.get(cid.session_id)
        device_revoked = device_status.revoked
        session_revoked = bool(session_state and session_state.revoked)
        session_expired = bool(
            session_state and _aware(session_state.expires_at) < now
        )

        # -- Recent history for this user, scanned once. --
        recent_denied = 0
        recent_face_failures = 0
        recent_failed_logins = 0
        device_seen_before = False
        resource_seen_before = False
        scanned = 0
        for entry in reversed(list(self._audit_source.list_entries())):
            scanned += 1
            if scanned > _MAX_HISTORY_SCAN:
                break
            if entry.user_id != user_id:
                continue
            if entry.device_id == cid.device_id:
                device_seen_before = True
            if entry.resource == cid.resource:
                resource_seen_before = True
            if _aware(entry.timestamp) < window_start:
                continue
            if entry.action in _DENIED_ACTIONS:
                recent_denied += 1
            elif entry.action == AuditEvent.FACE_VERIFY_FAILURE:
                recent_face_failures += 1
            elif entry.action == AuditEvent.LOGIN_FAILURE:
                recent_failed_logins += 1

        device_changed = not device_seen_before
        unusual_resource_access = not resource_seen_before

        classification = (cid.classification or "").strip().lower()
        resource_lower = cid.resource.lower()
        sensitive_resource_access = classification in self._sensitive_classifications or any(
            keyword in resource_lower for keyword in self._sensitive_keywords
        )

        # `device_mismatch` / `session_expired` / `revoked_device_or_session`
        # feed the *scored* factors only when this caller wants the risk
        # engine itself to weigh in on device/session revocation. When a
        # dedicated, authoritative check (AuthorizationService) runs
        # immediately after this call with its own well-typed errors and
        # audit events, those three are scored as "nothing unusual" here
        # to avoid a second, differently-shaped rejection for the exact
        # same fact — see the `collect()` docstring above.
        scored_device_mismatch = device_revoked if fold_device_session_revocation_into_score else False
        scored_session_expired = session_expired if fold_device_session_revocation_into_score else False
        scored_revoked_device_or_session = (
            (device_revoked or session_revoked) if fold_device_session_revocation_into_score else False
        )

        factors = RiskFactors(
            failed_login_count=recent_failed_logins,
            face_confidence=face_confidence,
            device_mismatch=scored_device_mismatch,
            session_expired=scored_session_expired,
            policy_failure_count=0,
            unusual_resource_access=unusual_resource_access,
            unusual_operation=False,
            sensitive_resource_access=sensitive_resource_access,
            repeated_denied_requests=recent_denied,
            repeated_face_failures=recent_face_failures,
            device_changed=device_changed,
            session_changed=False,
            intent_changed=False,
            lifecycle_changed=False,
            authorization_changed=False,
            revoked_device_or_session=scored_revoked_device_or_session,
        )

        signals_analyzed = (
            "device_status",
            "session_validity",
            "recent_denied_requests",
            "recent_face_failures",
            "recent_failed_logins",
            "device_history",
            "resource_history",
            "resource_sensitivity",
            "face_confidence",
        )

        patterns: list[str] = []
        if device_changed and sensitive_resource_access:
            patterns.append("new_device_accessing_sensitive_resource")
        if recent_denied >= 2 and device_changed:
            patterns.append("repeated_denials_from_new_device")
        if recent_face_failures >= 2:
            patterns.append("repeated_face_verification_failures")
        if device_revoked or session_revoked:
            patterns.append("revoked_device_or_session_reuse_attempt")
        if recent_failed_logins >= 2 and unusual_resource_access:
            patterns.append("credential_pressure_before_unfamiliar_resource_access")

        return CollectedContext(
            factors=factors,
            signals_analyzed=signals_analyzed,
            detected_patterns=tuple(patterns),
        )


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

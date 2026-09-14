"""
AuthorizationService — evaluates the CURRENT security state and turns
it into (a) an explicit authorize/reject decision, and (b) the
`SecurityState` snapshot that `crypto/` binds into the cryptographic
session.

This is the piece that makes "authorization state -> affects
cryptographic session state" true rather than just aspirational: the
app must call this, get an explicit `AuthorizationDecision`, and only
then may it derive a key. AES-GCM/HKDF do not and cannot discover a
revoked device or an expired session on their own — this service is
what makes that check happen, every time, before crypto runs.

Deliberately NOT this service's job (kept as separate, explicit gates
elsewhere, per the "clearly separate policy/risk/lifecycle/crypto
rejection" requirement):
    - risk assessment (policy.risk / the decrypt route)
    - face re-verification step-up (authentication.face_auth)
    - AEAD tag verification (crypto.aes_gcm)
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from typing import Protocol, Sequence

from intent.canonicalizer import compute_intent_hash
from intent.lifecycle import CRYPTO_ELIGIBLE_STATES, IntentState
from intent.schema import CID
from policy.config import PolicyRow, policy_context_overrides
from policy.engine import PolicyDecision, PolicyEngine
from policy.rules import PolicyContext

from .devices import DeviceRepository
from .errors import DeviceRevokedError, LifecycleRejectedError, PolicyRejectedError, SessionInvalidError
from .sessions import SessionRepository, is_session_valid
from .state import SecurityState, compute_authorization_state_hash, compute_policy_signature

DEFAULT_SESSION_TTL = timedelta(hours=1)


class PolicyConfigRepository(Protocol):
    """Satisfied by `api.repositories.PolicyRepository`. Kept as a
    Protocol, same pattern as `DeviceRepository`/`SessionRepository`,
    so this module stays unaware of Mongo."""

    def list_all(self) -> Sequence[PolicyRow]: ...


@dataclass(frozen=True)
class AuthorizationDecision:
    security_state: SecurityState
    authorization_state_hash: str
    policy_decision: PolicyDecision


class AuthorizationService:
    def __init__(
        self,
        device_repository: DeviceRepository,
        session_repository: SessionRepository,
        policy_engine: PolicyEngine | None = None,
        policy_config_repository: PolicyConfigRepository | None = None,
    ) -> None:
        self._devices = device_repository
        self._sessions = session_repository
        self._policy_engine = policy_engine or PolicyEngine()
        # Optional — omitting it (as every existing caller/test does)
        # preserves the previous fully-permissive PolicyContext
        # exactly. See policy.config for why this is the smallest
        # change that makes persisted policies affect enforcement.
        self._policy_config_repository = policy_config_repository

    def authorize(
        self,
        cid: CID,
        intent_id: int,
        intent_lifecycle_state: IntentState,
        user_id: int,
        requesting_user_role: str,
        now: datetime | None = None,
    ) -> AuthorizationDecision:
        """Explicitly verify current device/session/lifecycle/policy
        state and, only if all pass, return the `SecurityState` that
        the caller must bind into key derivation.

        Raises one of `authorization.errors.AuthorizationError`
        subclasses on rejection — the caller (API layer) is
        responsible for translating that into an HTTP response and an
        audit entry.
        """
        now = now or datetime.now(timezone.utc)

        device_status = self._devices.get_status(cid.device_id)
        if device_status.revoked:
            raise DeviceRevokedError(cid.device_id)

        session = self._sessions.get_or_create(
            cid.session_id, user_id=user_id, device_id=cid.device_id, ttl=DEFAULT_SESSION_TTL, now=now
        )
        valid, reason = is_session_valid(session, now)
        if not valid:
            raise SessionInvalidError(cid.session_id, reason or "invalid")

        if intent_lifecycle_state not in CRYPTO_ELIGIBLE_STATES:
            raise LifecycleRejectedError(intent_id, intent_lifecycle_state.value)

        overrides = {}
        if self._policy_config_repository is not None:
            overrides = policy_context_overrides(self._policy_config_repository.list_all())
        policy_context = PolicyContext(now=now, requesting_user_role=requesting_user_role, **overrides)
        policy_decision = self._policy_engine.evaluate(cid, policy_context)
        if not policy_decision.passed:
            raise PolicyRejectedError(
                tuple(f"{o.rule_name}: {o.reason}" for o in policy_decision.failures)
            )

        policy_signature = compute_policy_signature(policy_decision)
        security_state = SecurityState(
            intent_hash=compute_intent_hash(cid),
            operation=cid.operation,
            device_id=cid.device_id,
            session_id=cid.session_id,
            intent_lifecycle_state=intent_lifecycle_state,
            policy_decision_signature=policy_signature,
            session_version=session.version,
        )
        authorization_state_hash = compute_authorization_state_hash(security_state)

        return AuthorizationDecision(
            security_state=security_state,
            authorization_state_hash=authorization_state_hash,
            policy_decision=policy_decision,
        )

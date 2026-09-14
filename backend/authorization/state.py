"""
Continuous authorization state.

This module defines the *current security state* snapshot that CipherQ
treats as a first-class input to an active data-access cryptographic
session, and the deterministic hash used to bind that snapshot into
key derivation (see `crypto.key_derivation`) and AEAD associated data
(see `crypto.aes_gcm`).

Design note (what is bound vs. what is gated):

    Bound into the cryptographic session (this module):
        - intent_hash            (already existed — CID canonical hash)
        - operation               (already existed)
        - device_id / session_id  (already existed, in HKDF salt/info)
        - intent_lifecycle_state  (NEW — Draft/Approved/Used/... )
        - policy_decision_signature (NEW — current policy outcome)
        - session_version         (NEW — bumped on re-authorization)

    Explicit gate only, NOT baked into the hash (checked by
    `authorization.service.AuthorizationService` / the risk-aware
    decrypt route, before any crypto call):
        - device/session validity (revoked, expired)
        - intent lifecycle eligibility
        - policy pass/fail
        - risk level/action

    Risk is intentionally excluded from the bound hash: it is a noisy,
    continuous, per-request signal (QBER, face confidence, recent
    failed logins, ...), not a stable fact about the current security
    state. Folding it into the HKDF/AAD would make legitimate
    encrypt-then-decrypt round trips fail nondeterministically. Risk
    is enforced as an explicit reject/step-up gate instead — see
    `policy.risk` and `api/routers/decryption.py`.

    This split is deliberate and is documented further in
    `docs/architecture-design-document.md`.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from intent.lifecycle import IntentState
from policy.engine import PolicyDecision

_STATE_HASH_ALGORITHM = "sha256"
_STATE_PROTOCOL_TAG = "CIPHERQ-AUTHZ-STATE-v1"

# Lifecycle values that are "still authorized, unrevoked" for the
# purpose of the cryptographic binding hash. By the time a
# `SecurityState` is constructed, `AuthorizationService.authorize()`
# has already gated `intent_lifecycle_state` to
# `intent.lifecycle.CRYPTO_ELIGIBLE_STATES` ({APPROVED, USED}) — any
# other value (Draft/Expired/Archived/Destroyed) is rejected before
# reaching this point and never produces a `SecurityState` at all.
#
# Binding the *raw* literal state instead of this class would make
# every legitimate decrypt of a just-encrypted record fail: encryption
# always flips an intent APPROVED -> USED as an intentional side
# effect of a successful encrypt (see api/routers/encryption.py), so
# the hash computed at encrypt time (Approved) would never match the
# hash recomputed at decrypt time (Used) even though nothing
# security-relevant changed. Device/session revocation, policy
# changes, and session re-authorization are still fully captured by
# their own dedicated fields below, so collapsing Approved/Used into
# one class here does not weaken those checks.
_ACTIVE_LIFECYCLE_STATES = frozenset({IntentState.APPROVED, IntentState.USED})
_AUTHORIZED_ACTIVE_CLASS = "authorized-active"


def _lifecycle_authorization_class(state: IntentState) -> str:
    if state in _ACTIVE_LIFECYCLE_STATES:
        return _AUTHORIZED_ACTIVE_CLASS
    # Defensive fallback only — every real call path today rejects
    # non-crypto-eligible states before a SecurityState is built.
    return state.value


def compute_policy_signature(decision: PolicyDecision) -> str:
    """Deterministic fingerprint of *which rules ran and whether they
    passed*, right now. This stands in for "policy state/version": any
    change to the active rule set, or to the outcome any rule produces
    for this context, changes the signature.
    """
    outcomes = sorted(
        ({"rule": o.rule_name, "passed": o.passed} for o in decision.outcomes),
        key=lambda o: o["rule"],
    )
    payload = json.dumps(outcomes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.new(_STATE_HASH_ALGORITHM, payload).hexdigest()


@dataclass(frozen=True)
class SecurityState:
    """Snapshot of the security-relevant facts a crypto session is
    currently anchored to. Everything here is either already public
    (intent hash) or a coarse status flag/signature — never secret
    material.
    """

    intent_hash: str
    operation: str
    device_id: str
    session_id: str
    intent_lifecycle_state: IntentState
    policy_decision_signature: str
    session_version: int

    def as_dict(self) -> dict:
        return {
            "intent_hash": self.intent_hash,
            "operation": self.operation,
            "device_id": self.device_id,
            "session_id": self.session_id,
            # Hash on the authorization *class*, not the literal
            # lifecycle value — see `_lifecycle_authorization_class`.
            "intent_lifecycle_state": _lifecycle_authorization_class(self.intent_lifecycle_state),
            "policy_decision_signature": self.policy_decision_signature,
            "session_version": self.session_version,
        }


def compute_authorization_state_hash(state: SecurityState) -> str:
    """The value that gets folded into HKDF `info` and AES-GCM AAD.

    Changing ANY field of `SecurityState` — most importantly
    `intent_lifecycle_state`, `policy_decision_signature`, or
    `session_version` — produces an unrelated hash. That is the
    mechanism that lets a lifecycle transition, a policy change, or a
    fresh re-authorization invalidate an already-derived cryptographic
    session without any of those three needing to "know about" crypto.
    """
    payload = json.dumps(
        {"tag": _STATE_PROTOCOL_TAG, **state.as_dict()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.new(_STATE_HASH_ALGORITHM, payload).hexdigest()

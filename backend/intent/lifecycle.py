"""
Intent lifecycle state machine.

    Draft -> Approved -> Used -> Expired -> Archived -> Destroyed

Defaults applied here (see architecture doc, open question #3):
an Approved/Used intent may be used repeatedly within its validity
window — Used is not a terminal, single-shot state. It becomes
Expired once `valid_until` has passed, regardless of use count.
"""
from __future__ import annotations

from enum import Enum


class IntentState(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    REJECTED = "rejected"
    USED = "used"
    EXPIRED = "expired"
    ARCHIVED = "archived"
    DESTROYED = "destroyed"


class InvalidTransitionError(Exception):
    """Raised when a requested lifecycle transition is not permitted."""

    def __init__(self, current: "IntentState", target: "IntentState") -> None:
        self.current = current
        self.target = target
        super().__init__(
            f"Cannot transition intent from '{current.value}' to '{target.value}'"
        )


_ALLOWED_TRANSITIONS: dict[IntentState, set[IntentState]] = {
    IntentState.DRAFT: {IntentState.APPROVED, IntentState.REJECTED},
    IntentState.APPROVED: {IntentState.USED, IntentState.EXPIRED},
    IntentState.REJECTED: set(),
    IntentState.USED: {IntentState.USED, IntentState.EXPIRED},
    IntentState.EXPIRED: {IntentState.ARCHIVED},
    IntentState.ARCHIVED: {IntentState.DESTROYED},
    IntentState.DESTROYED: set(),
}


# Lifecycle states that may back ANY cryptographic operation at all.
# Draft has no approval yet; Expired/Archived/Destroyed have left the
# window where use is permitted. This is the single source of truth
# for "is this state crypto-eligible in general" — `authorization/`
# and `api/routers/encryption.py` both import it rather than each
# re-deriving their own set.
CRYPTO_ELIGIBLE_STATES = frozenset({IntentState.APPROVED, IntentState.USED})

# Encryption specifically is one-shot per approval: only a freshly
# APPROVED intent may enter the encrypt path. (Used is still
# crypto-eligible in general — see CRYPTO_ELIGIBLE_STATES above — but
# only for decryption, which is allowed to happen repeatedly against
# an already-Used intent.)
ENCRYPT_ELIGIBLE_STATES = frozenset({IntentState.APPROVED})


def allowed_next_states(current: IntentState) -> set[IntentState]:
    return set(_ALLOWED_TRANSITIONS.get(current, set()))


def validate_transition(current: IntentState, target: IntentState) -> None:
    """Raise InvalidTransitionError if `current -> target` is not permitted."""
    if target not in _ALLOWED_TRANSITIONS.get(current, set()):
        raise InvalidTransitionError(current, target)


def apply_transition(current: IntentState, target: IntentState) -> IntentState:
    """Validate and return the resulting state (does not persist anything)."""
    validate_transition(current, target)
    return target

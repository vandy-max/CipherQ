"""
Typed authorization errors.

Kept distinct per rejection category on purpose — the spec this module
implements requires the application to be able to tell a policy
rejection apart from a risk rejection, a lifecycle rejection, a
revoked device/session, or a stale (replayed) cryptographic context,
rather than collapsing everything into one generic "denied".
"""
from __future__ import annotations


class AuthorizationError(Exception):
    """Base class for every explicit continuous-authorization rejection."""


class DeviceRevokedError(AuthorizationError):
    def __init__(self, device_id: str) -> None:
        self.device_id = device_id
        super().__init__(f"device '{device_id}' is revoked")


class SessionInvalidError(AuthorizationError):
    def __init__(self, session_id: str, reason: str) -> None:
        self.session_id = session_id
        self.reason = reason
        super().__init__(f"session '{session_id}' is invalid: {reason}")


class LifecycleRejectedError(AuthorizationError):
    def __init__(self, intent_id: int, state: str) -> None:
        self.intent_id = intent_id
        self.state = state
        super().__init__(
            f"intent {intent_id} is not eligible for cryptographic use "
            f"in lifecycle state '{state}'"
        )


class PolicyRejectedError(AuthorizationError):
    def __init__(self, reasons: tuple[str, ...]) -> None:
        self.reasons = reasons
        super().__init__("policy evaluation failed: " + "; ".join(reasons))


class ReplayError(AuthorizationError):
    """A cryptographic session/context that is no longer the current
    one is being reused (e.g. an authorization state hash from before
    a re-authorization event)."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"replayed or stale cryptographic context: {detail}")

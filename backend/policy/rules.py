"""
Policy rules, evaluated against a (recreated) CID before HKDF ever runs.

Independent of and complementary to the crypto-layer's intent-hash
check: a changed CID field fails decryption two ways at once — the
canonical hash no longer matches (crypto/service.py), AND the relevant
policy rule fails here. Either one alone would be sufficient; having
both is deliberate defense-in-depth, not redundancy to be trimmed.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from intent.schema import CID


@dataclass(frozen=True)
class PolicyContext:
    """Everything a rule might need beyond the CID itself.

    Allow-list fields default to `None`, meaning "not restricted in
    this context" — an empty `frozenset()` would instead mean "nothing
    is allowed", which is a different (and confusing) thing to express
    accidentally via a default.
    """

    now: datetime
    requesting_user_role: str
    allowed_devices: frozenset[str] | None = None
    allowed_operations: frozenset[str] | None = None
    allowed_resources: frozenset[str] | None = None
    required_role_for_operation: dict[str, str] | None = None
    max_session_duration: timedelta = timedelta(hours=1)


@dataclass(frozen=True)
class RuleOutcome:
    rule_name: str
    passed: bool
    reason: str | None = None


class PolicyRule(ABC):
    name: str = "unnamed_rule"

    @abstractmethod
    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome: ...


class AllowedOperationRule(PolicyRule):
    name = "allowed_operation"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        if context.allowed_operations is None or cid.operation in context.allowed_operations:
            return RuleOutcome(self.name, True)
        return RuleOutcome(
            self.name, False, f"operation '{cid.operation}' is not in the allowed set"
        )


class AllowedDeviceRule(PolicyRule):
    name = "allowed_device"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        if context.allowed_devices is None or cid.device_id in context.allowed_devices:
            return RuleOutcome(self.name, True)
        return RuleOutcome(
            self.name, False, f"device '{cid.device_id}' is not in the allowed set"
        )


class SessionTimeoutRule(PolicyRule):
    name = "session_timeout"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        elapsed = context.now - cid.valid_from
        if elapsed <= context.max_session_duration:
            return RuleOutcome(self.name, True)
        return RuleOutcome(
            self.name,
            False,
            f"session age {elapsed} exceeds max duration {context.max_session_duration}",
        )


class ValidityPeriodRule(PolicyRule):
    name = "validity_period"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        if cid.valid_from <= context.now <= cid.valid_until:
            return RuleOutcome(self.name, True)
        return RuleOutcome(
            self.name,
            False,
            f"current time {context.now} is outside [{cid.valid_from}, {cid.valid_until}]",
        )


class ResourceMatchingRule(PolicyRule):
    name = "resource_matching"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        if context.allowed_resources is None or cid.resource in context.allowed_resources:
            return RuleOutcome(self.name, True)
        return RuleOutcome(
            self.name, False, f"resource '{cid.resource}' is not in the allowed set"
        )


class RoleMatchingRule(PolicyRule):
    name = "role_matching"

    def evaluate(self, cid: CID, context: PolicyContext) -> RuleOutcome:
        if not context.required_role_for_operation:
            return RuleOutcome(self.name, True)
        required = context.required_role_for_operation.get(cid.operation)
        if required is None or required == context.requesting_user_role:
            return RuleOutcome(self.name, True)
        return RuleOutcome(
            self.name,
            False,
            f"operation '{cid.operation}' requires role '{required}', "
            f"requester has '{context.requesting_user_role}'",
        )


def default_rules() -> list[PolicyRule]:
    """The standard rule set from the spec, in evaluation order."""
    return [
        AllowedOperationRule(),
        AllowedDeviceRule(),
        SessionTimeoutRule(),
        ValidityPeriodRule(),
        ResourceMatchingRule(),
        RoleMatchingRule(),
    ]

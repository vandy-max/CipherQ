"""
Turns persisted `Policy` rows (the `policies` table/collection, managed
via `api/routers/policies.py` and the Policy Management page) into the
`PolicyContext` allow-list overrides that `policy.rules` actually reads.

This is the missing link for requirement "persisted policies must
affect runtime authorization": `PolicyEngine` already runs
`default_rules()` unconditionally (defense-in-depth, unchanged), and
each rule already reads its allow-list from `PolicyContext` — but
until now every caller built a bare, unrestricted `PolicyContext`
(`allowed_devices=None`, `allowed_operations=None`, ...), so a rule
row saved in the database never reached the rule that was supposed to
enforce it.

Deliberately NOT a redesign: rule_type values are exactly the six
existing rule names from `policy.rules.default_rules()`
(`allowed_operation`, `allowed_device`, `session_timeout`,
`validity_period`, `resource_matching`, `role_matching`) — the same
strings the frontend's `PolicyManagementPage` already offers and the
same rule set already runs. Only inactive rows and unrecognized
rule_types are ignored, so a deployment with no configured policies
keeps today's fully-permissive default behavior — no test relying on
the current unrestricted default needs to change.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Protocol, Sequence


class PolicyRow(Protocol):
    """Structural shape this module needs from a `database.models.Policy`
    row — kept as a Protocol so this module never imports the Mongo
    layer."""

    rule_type: str
    config_json: dict
    active: bool


def policy_context_overrides(policies: Sequence[PolicyRow]) -> dict[str, Any]:
    """Build the `PolicyContext` keyword overrides implied by the given
    (already-fetched) policy rows. Inactive rows and unknown
    `rule_type` values are skipped. When more than one active row
    shares a `rule_type`, the last one (by input order) wins for
    scalar fields (`session_timeout`); set-valued fields
    (`allowed_operation`/`allowed_device`/`resource_matching`) union
    across rows instead of overwriting, since two active "allow this
    set" policies of the same type are naturally additive, not
    contradictory.
    """
    overrides: dict[str, Any] = {}

    for policy in policies:
        if not policy.active:
            continue
        config = policy.config_json or {}

        if policy.rule_type == "allowed_operation":
            values = config.get("operations")
            if values is not None:
                existing = overrides.get("allowed_operations", frozenset())
                overrides["allowed_operations"] = existing | frozenset(values)

        elif policy.rule_type == "allowed_device":
            values = config.get("devices")
            if values is not None:
                existing = overrides.get("allowed_devices", frozenset())
                overrides["allowed_devices"] = existing | frozenset(values)

        elif policy.rule_type == "resource_matching":
            values = config.get("resources")
            if values is not None:
                existing = overrides.get("allowed_resources", frozenset())
                overrides["allowed_resources"] = existing | frozenset(values)

        elif policy.rule_type == "role_matching":
            values = config.get("roles")
            if values is not None:
                existing = dict(overrides.get("required_role_for_operation") or {})
                existing.update(values)
                overrides["required_role_for_operation"] = existing

        elif policy.rule_type == "session_timeout":
            seconds = config.get("seconds")
            if seconds is not None:
                overrides["max_session_duration"] = timedelta(seconds=seconds)

        # "validity_period" has no PolicyContext field to override —
        # ValidityPeriodRule reads valid_from/valid_until off the CID
        # itself. An active row of that type simply confirms the rule
        # stays enabled, which it already always is.

    return overrides

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from intent.schema import CID

from .rules import PolicyContext, PolicyRule, RuleOutcome, default_rules


@dataclass(frozen=True)
class PolicyDecision:
    passed: bool
    outcomes: tuple[RuleOutcome, ...]

    @property
    def failures(self) -> tuple[RuleOutcome, ...]:
        return tuple(outcome for outcome in self.outcomes if not outcome.passed)


class PolicyEngine:
    """Runs a configured list of rules against a CID + context.

    Constructor-injected rule list, so the API layer can build the
    production rule set from the `policies` table while tests can pass
    a minimal hand-picked list.
    """

    def __init__(self, rules: Sequence[PolicyRule] | None = None) -> None:
        self._rules: list[PolicyRule] = list(rules) if rules is not None else default_rules()

    def evaluate(self, cid: CID, context: PolicyContext) -> PolicyDecision:
        outcomes = tuple(rule.evaluate(cid, context) for rule in self._rules)
        return PolicyDecision(passed=all(o.passed for o in outcomes), outcomes=outcomes)

"""
Lightweight, explainable ML risk-analysis layer.

Requirement (hackathon spec item 9, "AI-ASSISTED RISK ANALYSIS"): add a
small, explainable model over the SAME security signals the
deterministic `RiskEngine` (`policy/risk.py`) already uses, and surface
it as an *additional* advisory signal — not a replacement for, or sole
authority over, policy/authorization enforcement.

What this is:
    A hand-specified logistic-regression scorer. `w · x + b` fed
    through a sigmoid, producing a probability in [0, 1]. Logistic
    regression is used because it is inherently explainable: each
    feature's contribution to the final score is just
    `weight * feature_value`, so "why did this get flagged" is a
    direct, auditable readout (see `explain()` below) rather than a
    black box.

What this explicitly is NOT:
    - Not trained on real user data. CipherQ has no historical labeled
      security-incident dataset to train against. The coefficients
      below were chosen by hand to roughly track the same
      security intuition already encoded as weights in
      `policy.risk.RiskEngine` (repeated failures/anomalies matter
      more than a single occurrence; a revoked device/session is
      treated as maximally suspicious).
    - Not a claim of production-grade accuracy, precision, or recall.
      There is no accuracy number to report because there is no held-
      out labeled dataset to measure it against. Any UI or docs
      surfacing this must say "demo/prototype model" and must not
      fabricate a performance metric.
    - Not the final authority. `RiskEngine.assess()` (deterministic,
      threshold-based) remains what `authorization/` and the intent
      approval pipeline actually enforce. This module's output is
      informational: an extra "risk probability + explanation" signal
      that a caller (e.g. the `/api/risk/assess` response, or a future
      dashboard) can display alongside the deterministic verdict.

If real historical data becomes available, `MLRiskModel` can be
retrained (e.g. with `sklearn.linear_model.LogisticRegression`) without
changing its interface — `score()`/`explain()` callers do not need to
know whether the weights came from a hand-specification or a fit.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .risk import RiskFactors, RiskLevel

# Feature order is fixed and shared between `_features()` and
# `_WEIGHTS` below — each entry is (feature_name, weight). Weights are
# on a roughly comparable scale to `policy.risk._DEFAULT_WEIGHTS`,
# scaled down so `sigmoid(w . x + b)` saturates sensibly rather than
# immediately pinning to 0/1 for any single signal.
_WEIGHTS: list[tuple[str, float]] = [
    ("qber", 4.5),
    ("failed_login_count", 0.35),
    ("low_face_confidence", 2.2),
    ("device_mismatch", 2.2),
    ("session_expired", 2.6),
    ("rapid_access_attempts", 0.25),
    ("policy_failure_count", 0.9),
    ("unusual_resource_access", 1.1),
    ("unusual_operation", 0.9),
    ("sensitive_resource_access", 1.1),
    ("repeated_denied_requests", 0.55),
    ("repeated_face_failures", 0.5),
    ("device_changed", 1.4),
    ("session_changed", 0.9),
    ("intent_changed", 0.5),
    ("lifecycle_changed", 0.5),
    ("authorization_changed", 0.9),
    ("revoked_device_or_session", 5.5),
]
_BIAS = -3.2  # keeps an all-clear feature vector near a low probability

_FACE_CONFIDENCE_THRESHOLD = 0.6
_CAP = {
    "failed_login_count": 5,
    "rapid_access_attempts": 5,
    "policy_failure_count": 4,
    "repeated_denied_requests": 5,
    "repeated_face_failures": 5,
}

# Probability thresholds, deliberately mirroring RiskLevel's four
# buckets so ML output and deterministic output are easy to compare
# side by side even though they are computed independently.
_MEDIUM_P = 0.30
_HIGH_P = 0.60
_CRITICAL_P = 0.90


def _sigmoid(z: float) -> float:
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


def _features(factors: RiskFactors) -> dict[str, float]:
    def capped(value: int, key: str) -> float:
        return float(min(value, _CAP[key]))

    return {
        "qber": min(max(factors.qber, 0.0), 1.0),
        "failed_login_count": capped(factors.failed_login_count, "failed_login_count"),
        "low_face_confidence": 1.0
        if (factors.face_confidence is not None and factors.face_confidence < _FACE_CONFIDENCE_THRESHOLD)
        else 0.0,
        "device_mismatch": 1.0 if factors.device_mismatch else 0.0,
        "session_expired": 1.0 if factors.session_expired else 0.0,
        "rapid_access_attempts": capped(factors.rapid_access_attempts, "rapid_access_attempts"),
        "policy_failure_count": capped(factors.policy_failure_count, "policy_failure_count"),
        "unusual_resource_access": 1.0 if factors.unusual_resource_access else 0.0,
        "unusual_operation": 1.0 if factors.unusual_operation else 0.0,
        "sensitive_resource_access": 1.0 if factors.sensitive_resource_access else 0.0,
        "repeated_denied_requests": capped(factors.repeated_denied_requests, "repeated_denied_requests"),
        "repeated_face_failures": capped(factors.repeated_face_failures, "repeated_face_failures"),
        "device_changed": 1.0 if factors.device_changed else 0.0,
        "session_changed": 1.0 if factors.session_changed else 0.0,
        "intent_changed": 1.0 if factors.intent_changed else 0.0,
        "lifecycle_changed": 1.0 if factors.lifecycle_changed else 0.0,
        "authorization_changed": 1.0 if factors.authorization_changed else 0.0,
        "revoked_device_or_session": 1.0 if factors.revoked_device_or_session else 0.0,
    }


@dataclass(frozen=True)
class FeatureContribution:
    feature: str
    value: float
    weight: float
    contribution: float  # weight * value, in logit space


@dataclass(frozen=True)
class MLRiskAssessment:
    probability: float
    level: RiskLevel
    top_factors: tuple[FeatureContribution, ...]
    is_prototype: bool = True


class MLRiskModel:
    """Hand-specified logistic-regression risk scorer.

    See module docstring for exactly what "explainable" and
    "prototype" mean here. Weights/bias are intentionally
    constructor-overridable so a future retrained model can be
    swapped in without touching call sites.
    """

    def __init__(self, weights: dict[str, float] | None = None, bias: float = _BIAS) -> None:
        base = dict(_WEIGHTS)
        self._weights = {**base, **(weights or {})}
        self._bias = bias

    def assess(self, factors: RiskFactors, *, top_n: int = 3) -> MLRiskAssessment:
        feats = _features(factors)
        contributions = [
            FeatureContribution(
                feature=name,
                value=value,
                weight=self._weights.get(name, 0.0),
                contribution=value * self._weights.get(name, 0.0),
            )
            for name, value in feats.items()
        ]
        logit = self._bias + sum(c.contribution for c in contributions)
        probability = round(_sigmoid(logit), 4)

        if probability >= _CRITICAL_P:
            level = RiskLevel.CRITICAL
        elif probability >= _HIGH_P:
            level = RiskLevel.HIGH
        elif probability >= _MEDIUM_P:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        top = tuple(
            sorted((c for c in contributions if c.contribution > 0), key=lambda c: c.contribution, reverse=True)[
                :top_n
            ]
        )
        return MLRiskAssessment(probability=probability, level=level, top_factors=top)

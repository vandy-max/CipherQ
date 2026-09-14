"""
Qira — CipherQ Security Copilot.

This package is an *intelligence layer* on top of the existing,
already-authoritative security infrastructure (monitoring/, policy/,
authorization/, audit/). It never replaces the deterministic risk
engine or the continuous-monitoring state machine — see
`qira/policy.py` module docstring for the fail-safe authority model
this package is built around (identical in spirit to
`policy/ai_risk_service.py`'s "AI can only ever add caution, never
remove it" rule).
"""

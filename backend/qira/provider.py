"""
Real AI-provider integration for Qira's advisory contextual
assessment (Part 8/9/27 of the brief).

Configuration (server-side only, never sent to the frontend):

    AI_PROVIDER=anthropic          # currently supported: "anthropic"
    AI_API_KEY=sk-...
    AI_MODEL=claude-sonnet-4-6     # or another current Claude model

If configuration is missing/invalid, or the request fails, times out,
or the model returns something that doesn't validate against
`QiraAssessment`, this module raises `QiraProviderUnavailable` —
callers (see `service.py`) MUST catch this and fall back to the
deterministic baseline in `policy.py` rather than granting access or
crashing the request. This is the concrete implementation of Part 28
("If Qira fails, times out, gives malformed output, or the AI
provider is unavailable: DO NOT grant access because of AI failure").
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from .schema import QiraAssessment, QiraContext, RecommendedAction, SecurityState, TamperSeverity

_REQUEST_TIMEOUT_SECONDS = 12
_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_API_VERSION = "2023-06-01"
_DEFAULT_MODEL = "claude-sonnet-4-6"

_VALID_STATES = {s.value for s in SecurityState}
_VALID_SEVERITIES = {s.value for s in TamperSeverity}
_VALID_ACTIONS = {a.value for a in RecommendedAction}


class QiraProviderUnavailable(Exception):
    """Raised for ANY failure mode: missing config, network error,
    timeout, non-2xx response, or malformed/invalid JSON. Deliberately
    a single exception type — callers don't get to treat some AI
    failures as "safe to ignore"; see module docstring."""


@dataclass(frozen=True)
class ProviderConfig:
    provider: str
    api_key: str
    model: str


def load_provider_config() -> ProviderConfig:
    provider = (os.environ.get("AI_PROVIDER") or "").strip().lower()
    api_key = (os.environ.get("AI_API_KEY") or "").strip()
    model = (os.environ.get("AI_MODEL") or "").strip() or _DEFAULT_MODEL

    if not provider or not api_key:
        raise QiraProviderUnavailable(
            "AI_PROVIDER/AI_API_KEY are not configured — Qira's advisory "
            "layer is unavailable; the deterministic security policy "
            "still applies."
        )
    if provider != "anthropic":
        raise QiraProviderUnavailable(f"Unsupported AI_PROVIDER: {provider!r}")
    return ProviderConfig(provider=provider, api_key=api_key, model=model)


_SYSTEM_PROMPT = """You are Qira, the CipherQ Security Copilot. You analyze REAL, \
already-collected application security context for one authenticated session and \
return ONLY a JSON object — no prose, no markdown fences, nothing else.

You are an ADVISORY layer. A deterministic backend policy has already computed a \
baseline severity from confirmed signals; you may recommend escalating caution based \
on patterns in the context (e.g. multiple weaker signals correlating), but you cannot \
manufacture certainty from nothing, and you must never recommend something less \
cautious than what the deterministic signals already indicate.

Return EXACTLY this JSON shape:
{
  "security_state": "SECURE" | "SECURITY_WARNING" | "COMPROMISED",
  "severity": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "reason": "<one or two sentence human-readable explanation, grounded only in the \
provided context, no speculation beyond it>",
  "confidence": <float 0.0-1.0>,
  "recommended_action": "NONE" | "MONITOR" | "REAUTHENTICATE" | "REVOKE",
  "signals": ["<short_signal_name>", ...]
}

Only use signal names that are actually present/derivable from the given context. \
Never invent a user identity, location, or event that isn't in the context. \
IMPORTANT: `audit_chain_intact=false` is a SEPARATE SYSTEM-INTEGRITY ALERT. Do not \
escalate the current session's severity or security_state solely because the audit \
chain is invalid. Base session risk on current monitoring, identity, authorization, \
and risk telemetry; the frontend will display the audit alert separately."""


def assess(context: QiraContext, baseline_severity: str, baseline_reason: str) -> QiraAssessment:
    """Calls the configured AI provider and returns a VALIDATED
    `QiraAssessment`. Raises `QiraProviderUnavailable` on any problem
    — never returns a partially-valid or best-effort object."""
    config = load_provider_config()

    user_prompt = (
        "Current safe security context (already collected by existing backend "
        "services — do not ask for more):\n"
        + json.dumps(context.as_dict(), indent=2)
        + f"\n\nDeterministic backend baseline (the floor — do not go below this): "
        f"severity={baseline_severity}, reason={baseline_reason!r}\n\n"
        "Return the JSON object described in your instructions now."
    )

    body = json.dumps(
        {
            "model": config.model,
            "max_tokens": 500,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": user_prompt}],
        }
    ).encode("utf-8")

    request = urllib.request.Request(
        _ANTHROPIC_API_URL,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": config.api_key,
            "anthropic-version": _ANTHROPIC_API_VERSION,
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        raise QiraProviderUnavailable(f"AI provider request failed: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise QiraProviderUnavailable(f"AI provider returned invalid JSON envelope: {exc}") from exc

    text = _extract_text(payload)
    if text is None:
        raise QiraProviderUnavailable("AI provider response had no text content block")

    return _parse_and_validate(text)


def _extract_text(payload: dict) -> str | None:
    for block in payload.get("content", []):
        if block.get("type") == "text" and block.get("text"):
            return block["text"]
    return None


def _parse_and_validate(text: str) -> QiraAssessment:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise QiraProviderUnavailable(f"AI provider output is not valid JSON: {exc}") from exc

    required = {"security_state", "severity", "reason", "confidence", "recommended_action", "signals"}
    missing = required - data.keys()
    if missing:
        raise QiraProviderUnavailable(f"AI provider output missing fields: {sorted(missing)}")

    if data["security_state"] not in _VALID_STATES:
        raise QiraProviderUnavailable(f"invalid security_state: {data['security_state']!r}")
    if data["severity"] not in _VALID_SEVERITIES:
        raise QiraProviderUnavailable(f"invalid severity: {data['severity']!r}")
    if data["recommended_action"] not in _VALID_ACTIONS:
        raise QiraProviderUnavailable(f"invalid recommended_action: {data['recommended_action']!r}")
    if not isinstance(data["confidence"], (int, float)) or not (0.0 <= float(data["confidence"]) <= 1.0):
        raise QiraProviderUnavailable(f"invalid confidence: {data['confidence']!r}")
    if not isinstance(data["reason"], str) or not data["reason"].strip():
        raise QiraProviderUnavailable("invalid/empty reason")
    if not isinstance(data["signals"], list) or not all(isinstance(s, str) for s in data["signals"]):
        raise QiraProviderUnavailable("invalid signals list")

    return QiraAssessment(
        security_state=SecurityState(data["security_state"]),
        severity=TamperSeverity(data["severity"]),
        reason=data["reason"].strip()[:500],
        confidence=float(data["confidence"]),
        recommended_action=RecommendedAction(data["recommended_action"]),
        signals=tuple(s.strip()[:60] for s in data["signals"][:12] if s.strip()),
    )


_ASK_SYSTEM_PROMPT = """You are Qira, the CipherQ Security Copilot. Answer the user's \
question about their OWN current security context, using ONLY the JSON context provided. \
You are read-only here: you cannot take any action, grant access, change any state, or \
promise that you have done so. If asked to do something (unlock, approve, bypass, disable \
monitoring, restore access), explain that only the deterministic backend policy / an \
administrator can do that, never you. Keep answers concise (2-4 sentences). Do not invent \
information that is not present in the context."""


def deterministic_safe_answer(context: QiraContext, question: str) -> str:
    """Safe, local, read-only Qira guidance.

    Chat is intentionally limited to coarse security guidance. It never
    exposes identifiers, credentials, raw audit records, face data, tokens,
    or private telemetry, and it never performs an action.
    """
    q = (question or "").strip().lower()

    if not q:
        return (
            "Hi! I'm Qira, your CipherQ Security Copilot. How can I help? "
            "You can check your risk, audit integrity, device trust, monitoring, "
            "or ask what to do next."
        )

    # Friendly conversation stays local and never needs an AI provider.
    greetings = {"hi", "hello", "hey", "hii", "helo", "good morning", "good afternoon", "good evening"}
    if q in greetings or any(q.startswith(g + " ") for g in greetings):
        return (
            "Hello! 👋 I'm Qira, your CipherQ Security Copilot. How can I help? "
            "You can check your risk, audit integrity, device trust, monitoring, "
            "or ask what to do next."
        )

    # Security-control requests are always explicitly read-only.
    if any(k in q for k in ("unlock", "bypass", "approve", "disable monitoring", "restore access", "revoke", "change security")):
        return (
            "I cannot unlock, approve, bypass, disable monitoring, or change security controls. "
            "Those actions must follow CipherQ's authorized backend policy and recovery flow. "
            "I can explain your risk, audit integrity, device trust, monitoring, or next steps."
        )

    risk = context.risk_level.replace("_", " ").upper()
    score = round(float(context.risk_score), 1)

    if any(k in q for k in ("audit", "tamper", "integrity", "hash chain")):
        if context.audit_chain_intact:
            return (
                "Audit integrity is VERIFIED. The audit chain passed its genesis, "
                "continuity, hash-recalculation, required-field, and chronological-order checks. "
                "Would you like me to check something else?"
            )
        return (
            "Audit integrity is FAILED and requires review. This means at least one "
            "audit-chain integrity measurement did not pass. It is a system-integrity alert "
            "and is separate from your current live-session risk verdict. Would you like me to check something else?"
        )

    if any(k in q for k in ("risk score", "risk level", "risk", "minus risk", "my risk")):
        return (
            f"Your current risk assessment is {risk} with a score of {score}/100. "
            "The score comes from authoritative monitoring and authorization telemetry. "
            "Would you like me to check something else?"
        )

    if any(k in q for k in ("device", "trusted", "trust")):
        if context.device_revoked:
            return (
                "Your current device is not trusted because it is revoked. "
                "Recovery must follow the authorized administrator or reauthentication flow. "
                "Would you like me to explain the next step?"
            )
        return "Your current device is trusted. Would you like me to check your monitoring status next?"

    if any(k in q for k in ("monitoring", "camera", "liveness", "continuous monitoring")):
        monitoring = context.monitoring_status.replace("_", " ").title()
        live = "confirmed" if context.liveness else "not confirmed"
        return (
            f"Continuous monitoring is {monitoring.lower()}, and liveness is {live}. "
            "Qira can explain the monitoring state, but it cannot disable monitoring or grant access. "
            "Would you like me to explain your risk next?"
        )

    if any(k in q for k in (
        "what should i do", "what do i do", "next", "help", "guide", "how do i",
        "what can i do", "action", "problem", "issue"
    )):
        if context.session_revoked or context.device_revoked:
            return (
                "Your access state requires recovery. Follow the authorized reauthentication or "
                "administrator recovery flow shown by CipherQ; Qira cannot bypass it. "
                "Would you like me to check your device or monitoring status?"
            )
        if context.consecutive_face_failures > 0 or not context.liveness:
            return (
                "Keep the camera available and complete the requested face verification if prompted. "
                "Avoid closing or blocking the monitoring session while it is active. "
                "Would you like me to explain your current risk?"
            )
        return (
            "No immediate action is required from the current monitoring state. Keep the session active "
            "and follow any reauthentication prompt if CipherQ displays one. Would you like me to check your risk?"
        )

    # Unknown/general questions are deliberately answered without an external
    # provider. This prevents ordinary chat such as "hello" from ever turning
    # into an Internal Server Error and keeps Qira inside its safe guidance scope.
    return (
        "I can help with CipherQ security guidance, but I don't handle confidential data or take security actions. "
        "You can check your risk, audit integrity, device trust, monitoring, or ask what to do next. "
        "Which would you like to check?"
    )


def ask(context: QiraContext, question: str) -> str:
    """Read-only Qira chat.

    The conversational widget is deliberately local and deterministic. The
    optional AI provider remains available for the separate security
    assessment path, but normal chat must never depend on external AI
    configuration, network access, or provider availability.
    """
    return deterministic_safe_answer(context, (question or "")[:2000])


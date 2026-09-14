"""
Authorization-state-bound key derivation.

    Quantum Session Material ----+
                                   |--> HKDF-SHA256 --> Ephemeral AES-256 Key
    Intent Hash + Authorization ---+
    State Hash

The raw quantum key is never used for encryption. It is HKDF input
key material (IKM); the derived key is scoped to one specific
(session, intent, operation, CURRENT authorization/security state)
combination:

    IKM  = quantum_shared_key_bytes
    salt = session_id.encode()                 (binds to this session)
    info = b"CIPHERQ-v2|" + intent_hash + b"|" + operation.encode()
           + b"|" + device_id.encode() + b"|" + authorization_state_hash.encode()

`authorization_state_hash` (see `authorization.state`) folds in the
current intent lifecycle state, the current policy decision signature,
and the current session version — the fields that make this "continuous
authorization-bound cryptography" rather than a purely static binding.
It is computed by `authorization.AuthorizationService` and must be
supplied by the caller; this module never computes it itself, so the
crypto layer stays independent of policy/lifecycle/session concerns
(see module docstring in `crypto/service.py`).

Folding `device_id` into `info` (alongside the policy engine's own
device check) gives defense-in-depth at the crypto layer itself: even
if a policy check were ever bypassed, decrypting from the wrong device
still derives the wrong AES key.

Changing ANY of session_id, intent_hash, operation, device_id, or
authorization_state_hash produces an unrelated 256-bit key — this is
the mechanism that makes "same quantum key, different intent, or
different current authorization state" fail to decrypt, which is the
project's core research claim.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PROTOCOL_TAG = b"CIPHERQ-v2"
_AES_256_KEY_LENGTH = 32  # bytes


def derive_intent_bound_key(
    quantum_key_bytes: bytes,
    intent_hash: str,
    session_id: str,
    operation: str,
    device_id: str,
    authorization_state_hash: str,
) -> bytes:
    """Derive a 256-bit AES key bound to this exact intent context AND
    the current authorization/security state.

    Raises ValueError on empty/missing inputs — an authorization-bound
    key must never be derivable from partial or ambiguous context.
    """
    if not quantum_key_bytes:
        raise ValueError("quantum_key_bytes must not be empty")
    if not intent_hash:
        raise ValueError("intent_hash must not be empty")
    if not session_id:
        raise ValueError("session_id must not be empty")
    if not operation:
        raise ValueError("operation must not be empty")
    if not device_id:
        raise ValueError("device_id must not be empty")
    if not authorization_state_hash:
        raise ValueError("authorization_state_hash must not be empty")

    info = (
        _PROTOCOL_TAG
        + b"|"
        + intent_hash.encode("utf-8")
        + b"|"
        + operation.encode("utf-8")
        + b"|"
        + device_id.encode("utf-8")
        + b"|"
        + authorization_state_hash.encode("utf-8")
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=_AES_256_KEY_LENGTH,
        salt=session_id.encode("utf-8"),
        info=info,
    )
    return hkdf.derive(quantum_key_bytes)

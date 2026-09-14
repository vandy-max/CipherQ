"""
Encryption/decryption orchestration for one (CID, quantum key,
authorization state) triple.

This is deliberately the only place in `crypto/` that talks to
`intent/`. It does NOT talk to `policy/`, `authorization/`, or
`audit/` directly — those run around this service (in `api/`), not
inside it, so the core cryptographic primitive stays testable in
isolation from policy/authorization decisions. The API layer is
responsible for calling `authorization.AuthorizationService.authorize`
first and passing this service the resulting
`authorization_state_hash` — this service treats it as an opaque,
already-validated string and simply binds it in.
"""
from __future__ import annotations

from dataclasses import dataclass

from intent import CID, compute_intent_hash

from .aes_gcm import EncryptionEnvelope, decrypt, encrypt
from .key_derivation import derive_intent_bound_key


class IntentHashMismatchError(Exception):
    """Raised when a recreated CID's canonical hash does not match the
    hash the ciphertext was originally encrypted under.

    This is the primary rejection path for a changed purpose, device,
    resource, operation, session, or validity window: any of those
    changes the canonical hash, so this error fires *before* any key
    derivation or AES call is attempted.
    """

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Intent hash mismatch: stored={expected}, recreated={actual}"
        )


class AuthorizationStateMismatchError(Exception):
    """Raised when the CURRENT authorization/security state hash does
    not match the one this ciphertext was bound to at encryption time.

    This is distinct from `IntentHashMismatchError`: the CID itself
    can be byte-for-byte identical while the surrounding security
    state (intent lifecycle, policy decision, session version) has
    moved on — e.g. the intent expired, a policy rule now fails, or
    the session was re-authorized since. This is the explicit
    "cryptographic context mismatch" rejection path required by the
    continuous-authorization design: it fires before any AES call, so
    a stale/replayed authorization context never even reaches AEAD
    verification.
    """

    def __init__(self, expected: str, actual: str) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Authorization state mismatch: stored={expected}, current={actual}"
        )


@dataclass(frozen=True)
class EncryptionService:
    """Stateless facade: quantum key + CID + authorization state ->
    ephemeral AES-GCM envelope, and back. Safe to construct per-request
    or share as a singleton."""

    def encrypt_for_intent(
        self,
        plaintext: bytes,
        quantum_key_bytes: bytes,
        cid: CID,
        authorization_state_hash: str,
    ) -> EncryptionEnvelope:
        intent_hash = compute_intent_hash(cid)

        aes_key = derive_intent_bound_key(
            quantum_key_bytes=quantum_key_bytes,
            intent_hash=intent_hash,
            session_id=cid.session_id,
            operation=cid.operation,
            device_id=cid.device_id,
            authorization_state_hash=authorization_state_hash,
        )
        envelope = encrypt(plaintext, aes_key, intent_hash, extra_aad=authorization_state_hash)
        return EncryptionEnvelope(
            ciphertext=envelope.ciphertext,
            nonce=envelope.nonce,
            auth_tag=envelope.auth_tag,
            intent_hash=envelope.intent_hash,
            created_at=envelope.created_at,
            authorization_state_hash=authorization_state_hash,
        )

    def decrypt_for_intent(
        self,
        envelope: EncryptionEnvelope,
        expected_intent_hash: str,
        quantum_key_bytes: bytes,
        recreated_cid: CID,
        current_authorization_state_hash: str,
    ) -> bytes:
        """Recreate -> canonicalize -> hash -> compare (intent) ->
        compare (authorization state) -> HKDF -> decrypt.

        Both comparisons happen before any key derivation or AES call,
        so a changed intent field and a changed authorization state
        each produce their own explicit, distinguishable error.
        """
        recreated_hash = compute_intent_hash(recreated_cid)
        if recreated_hash != expected_intent_hash:
            raise IntentHashMismatchError(expected_intent_hash, recreated_hash)

        if envelope.authorization_state_hash and (
            current_authorization_state_hash != envelope.authorization_state_hash
        ):
            raise AuthorizationStateMismatchError(
                envelope.authorization_state_hash, current_authorization_state_hash
            )

        aes_key = derive_intent_bound_key(
            quantum_key_bytes=quantum_key_bytes,
            intent_hash=recreated_hash,
            session_id=recreated_cid.session_id,
            operation=recreated_cid.operation,
            device_id=recreated_cid.device_id,
            authorization_state_hash=current_authorization_state_hash,
        )
        return decrypt(
            envelope.ciphertext,
            envelope.nonce,
            envelope.auth_tag,
            aes_key,
            recreated_hash,
            extra_aad=current_authorization_state_hash,
        )

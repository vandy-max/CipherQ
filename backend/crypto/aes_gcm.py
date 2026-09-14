"""
AES-256-GCM authenticated encryption.

Only ciphertext, nonce, and authentication tag are ever produced for
storage — the key itself is never returned to a caller for
persistence (callers hold it only long enough to call `encrypt`).

The intent hash is passed as AEAD associated data (AAD), not just used
to derive the key. This means even a hypothetical bug that let stored
ciphertext/nonce/tag get associated with the *wrong* stored
`intent_hash` value would still fail authentication — the hash is
cryptographically bound into the tag itself, not just used upstream.

`extra_aad` (optional) lets a caller bind additional public context —
CipherQ uses this for the authorization state hash — into the same
AEAD tag, without this module needing to know what that context means.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LENGTH = 12  # 96-bit, recommended nonce size for AES-GCM
_TAG_LENGTH = 16  # 128-bit authentication tag
_AES_256_KEY_LENGTH = 32  # bytes


@dataclass(frozen=True)
class EncryptionEnvelope:
    """Everything safe to persist for one encrypted record. No key
    material is ever part of this object."""

    ciphertext: bytes
    nonce: bytes
    auth_tag: bytes
    intent_hash: str
    created_at: datetime
    # Public metadata only — the authorization state hash this
    # envelope was bound to at encryption time (see
    # authorization.state). Empty string for envelopes built without
    # that binding (kept optional so existing direct callers of
    # `encrypt()`/tests are unaffected).
    authorization_state_hash: str = ""


def _build_aad(intent_hash: str, extra_aad: str | None) -> bytes:
    if extra_aad:
        return f"{intent_hash}|{extra_aad}".encode("utf-8")
    return intent_hash.encode("utf-8")


def encrypt(
    plaintext: bytes, key: bytes, intent_hash: str, extra_aad: str | None = None
) -> EncryptionEnvelope:
    if len(key) != _AES_256_KEY_LENGTH:
        raise ValueError(f"AES-256-GCM requires a {_AES_256_KEY_LENGTH}-byte key")
    if not intent_hash:
        raise ValueError("intent_hash must not be empty")

    nonce = os.urandom(_NONCE_LENGTH)
    aesgcm = AESGCM(key)
    aad = _build_aad(intent_hash, extra_aad)
    sealed = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext, tag = sealed[:-_TAG_LENGTH], sealed[-_TAG_LENGTH:]

    return EncryptionEnvelope(
        ciphertext=ciphertext,
        nonce=nonce,
        auth_tag=tag,
        intent_hash=intent_hash,
        created_at=datetime.now(timezone.utc),
    )


def decrypt(
    ciphertext: bytes,
    nonce: bytes,
    auth_tag: bytes,
    key: bytes,
    intent_hash: str,
    extra_aad: str | None = None,
) -> bytes:
    """Raises `cryptography.exceptions.InvalidTag` on any mismatch —
    wrong key, wrong nonce, wrong tag, or wrong intent_hash/extra_aad
    (AAD)."""
    if len(key) != _AES_256_KEY_LENGTH:
        raise ValueError(f"AES-256-GCM requires a {_AES_256_KEY_LENGTH}-byte key")
    if not intent_hash:
        raise ValueError("intent_hash must not be empty")

    aesgcm = AESGCM(key)
    aad = _build_aad(intent_hash, extra_aad)
    sealed = ciphertext + auth_tag
    return aesgcm.decrypt(nonce, sealed, aad)

"""
JWT issuance and verification.

Same core pattern as the reference project: HS256, `sub` claim cast to
a string (PyJWT/RFC 7519 requires this), an `exp` claim for expiry.
Reimplemented as an injectable class (secret/algorithm/TTL are
constructor args, not module globals) so it's usable as a FastAPI
dependency and swappable in tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt as pyjwt


class TokenExpiredError(Exception):
    pass


class InvalidTokenError(Exception):
    pass


@dataclass(frozen=True)
class TokenPayload:
    user_id: int
    username: str
    role: str
    expires_at: datetime


class JWTService:
    def __init__(self, secret: str, algorithm: str = "HS256", ttl_hours: int = 24) -> None:
        if not secret:
            raise ValueError("JWT secret must not be empty")
        self._secret = secret
        self._algorithm = algorithm
        self._ttl = timedelta(hours=ttl_hours)

    def create_token(self, user_id: int, username: str, role: str) -> str:
        expires_at = datetime.now(timezone.utc) + self._ttl
        payload = {
            "sub": str(user_id),
            "username": username,
            "role": role,
            "exp": expires_at,
        }
        return pyjwt.encode(payload, self._secret, algorithm=self._algorithm)

    def decode_token(self, token: str) -> TokenPayload:
        try:
            payload = pyjwt.decode(token, self._secret, algorithms=[self._algorithm])
        except pyjwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("token has expired") from exc
        except pyjwt.InvalidTokenError as exc:
            raise InvalidTokenError("token is invalid") from exc

        return TokenPayload(
            user_id=int(payload["sub"]),
            username=payload["username"],
            role=payload.get("role", "user"),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        )

"""
Registration/login orchestration — the service `api/` routers call
into, so route handlers stay thin per the "no business logic inside
routes" requirement.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .jwt_service import JWTService
from .password import generate_salt, hash_password, verify_password

_MIN_PASSWORD_LENGTH = 8  # reference project used 4; raised for this build


@dataclass(frozen=True)
class UserRecord:
    id: int
    username: str
    email: str
    password_hash: str
    salt: str
    role: str


class UsernameTakenError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


class UserRepository(Protocol):
    def get_by_username(self, username: str) -> UserRecord | None: ...
    def create(
        self, username: str, email: str, password_hash: str, salt: str, role: str
    ) -> UserRecord: ...


class InMemoryUserRepository:
    """Reference/test implementation only — not for production use."""

    def __init__(self) -> None:
        self._by_id: dict[int, UserRecord] = {}
        self._by_username: dict[str, int] = {}
        self._next_id = 1

    def get_by_username(self, username: str) -> UserRecord | None:
        user_id = self._by_username.get(username)
        return self._by_id.get(user_id) if user_id is not None else None

    def create(
        self, username: str, email: str, password_hash: str, salt: str, role: str
    ) -> UserRecord:
        user = UserRecord(
            id=self._next_id,
            username=username,
            email=email,
            password_hash=password_hash,
            salt=salt,
            role=role,
        )
        self._by_id[user.id] = user
        self._by_username[username] = user.id
        self._next_id += 1
        return user


@dataclass(frozen=True)
class AuthResult:
    token: str
    user_id: int
    username: str
    role: str


class AuthenticationService:
    def __init__(self, repository: UserRepository, jwt_service: JWTService) -> None:
        self._repository = repository
        self._jwt_service = jwt_service

    def register(
        self, username: str, email: str, password: str, role: str = "user"
    ) -> AuthResult:
        username = username.strip()
        if not username or not password:
            raise ValueError("username and password are required")
        if len(password) < _MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {_MIN_PASSWORD_LENGTH} characters")
        if self._repository.get_by_username(username) is not None:
            raise UsernameTakenError(f"username '{username}' is already taken")

        salt = generate_salt()
        password_hash = hash_password(password, salt)
        user = self._repository.create(username, email.strip(), password_hash, salt, role)
        token = self._jwt_service.create_token(user.id, user.username, user.role)
        return AuthResult(token=token, user_id=user.id, username=user.username, role=user.role)

    def login(self, username: str, password: str) -> AuthResult:
        user = self._repository.get_by_username(username.strip())
        if user is None or not verify_password(password, user.salt, user.password_hash):
            raise InvalidCredentialsError("invalid username or password")
        token = self._jwt_service.create_token(user.id, user.username, user.role)
        return AuthResult(token=token, user_id=user.id, username=user.username, role=user.role)

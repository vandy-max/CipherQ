from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import database.session  # noqa: F401 — importing performs the MongoDB
# production fail-fast check (auth + TLS required) the same way
# get_jwt_service() below does for JWT_SECRET; see database/session.py.
from database.encrypted_store import encryption_enabled

from .dependencies import get_jwt_service
from .routers import (
    audit,
    auth,
    authorization,
    decryption,
    encryption,
    face,
    intent,
    location,
    monitoring,
    policies,
    quantum,
    reauth_requests,
    risk,
    security,
    users,
)

app = FastAPI(
    title="Intent-Bound Quantum Cryptography API",
    version="0.1.0",
    description=(
        "Binds BB84-derived quantum keys to a Cryptographic Intent "
        "Descriptor (CID) via HKDF, enforced by a policy engine, "
        "lifecycle management, adaptive risk assessment, and a "
        "tamper-evident audit log."
    ),
)

# Fail fast at startup (not on the first incoming request) if
# APP_ENV=production and JWT_SECRET is unset — see
# api/dependencies.py::get_jwt_service. Every other environment keeps
# working unchanged even if this raises nothing.
get_jwt_service()

# ---------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------
# Development: permissive localhost/127.0.0.1 defaults so the Vite dev
# server (any port) keeps working out of the box.
# Production (APP_ENV=production): origins must come from the
# ALLOWED_ORIGINS environment variable (comma-separated). No wildcard
# is ever combined with allow_credentials=True — that combination is
# rejected by browsers anyway and is a real security footgun if a
# server ever did honor it.
DEV_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]


def resolve_cors_origins(app_env: str, raw_allowed_origins: str) -> list[str]:
    """Pure decision logic, factored out so it can be unit-tested
    directly (see tests/test_production_hardening.py)."""
    app_env = (app_env or "development").strip().lower()
    if app_env != "production":
        return DEV_CORS_ORIGINS
    origins = [origin.strip() for origin in raw_allowed_origins.split(",") if origin.strip()]
    if not origins:
        raise RuntimeError(
            "ALLOWED_ORIGINS is not set. Refusing to start with APP_ENV=production and "
            "no allowed CORS origins configured — set ALLOWED_ORIGINS to a comma-separated "
            "list of allowed production origins (e.g. "
            "'https://cipherq-frontend.onrender.com')."
        )
    return origins


_allowed_origins = resolve_cors_origins(
    os.environ.get("APP_ENV", "development"), os.environ.get("ALLOWED_ORIGINS", "")
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(intent.router)
app.include_router(encryption.router)
app.include_router(decryption.router)
app.include_router(audit.router)
app.include_router(policies.router)
app.include_router(quantum.router)
app.include_router(risk.router)
app.include_router(face.router)
app.include_router(authorization.router)
app.include_router(location.router)
app.include_router(monitoring.router)
app.include_router(security.router)
app.include_router(users.router)
app.include_router(reauth_requests.router)


@app.get("/api/health", tags=["health"])
def health() -> dict:
    """Non-secret runtime health information for local troubleshooting."""
    from database.session import MONGODB_DATABASE

    return {
        "status": "ok",
        "database": MONGODB_DATABASE,
        "application_encryption": encryption_enabled(),
    }

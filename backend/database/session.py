"""
MongoDB client and database access.

MONGODB_URI and MONGODB_DATABASE are read from the environment, e.g.:
  MONGODB_URI=mongodb://localhost:27017
  MONGODB_DATABASE=ibqc

Production hardening (see docs/SECURITY_MONGODB.md for the full
picture — authentication, TLS, encryption-at-rest, key management,
backups):

  APP_ENV=production refuses to start (see `assert_production_ready`
  below, called from `api/main.py` exactly like the existing JWT
  secret / CORS origin fail-fast checks) unless MONGODB_URI:
    - is not the bare local development default, and
    - carries credentials (a `user:pass@` authority) or an explicit
      `authSource`, and
    - requests TLS (`tls=true` / `ssl=true`, or a `mongodb+srv://`
      scheme, which implies TLS).

  This module never itself enables MongoDB's native
  encryption-at-rest — that is a `mongod`/Atlas *server*-side
  configuration (WiredTiger `--enableEncryption`, an Atlas cluster
  setting, etc.), not a pymongo client option, and is documented
  separately rather than faked here.
"""
from __future__ import annotations

import os
from collections.abc import Generator
from urllib.parse import urlsplit

from dotenv import load_dotenv

# Load backend/.env before any configuration is read. Explicit environment
# variables still win because load_dotenv() does not override the process env.
load_dotenv()

from pymongo import MongoClient
from pymongo.collection import ReturnDocument
from pymongo.database import Database

from database.encrypted_store import EncryptedDatabase, encryption_enabled

MONGODB_URI = os.environ.get("MONGODB_URI", "mongodb://localhost:27017")
MONGODB_DATABASE = os.environ.get("MONGODB_DATABASE", "ibqc")

# Optional: path to a CA bundle for verifying the MongoDB server's TLS
# certificate (e.g. a private CA for a self-hosted replica set, or a
# managed provider's bundle). Left unset, pymongo/the OS trust store's
# defaults apply — the right choice for MongoDB Atlas.
MONGODB_TLS_CA_FILE = os.environ.get("MONGODB_TLS_CA_FILE") or None

# Fail fast rather than hang indefinitely if MongoDB is unreachable
# (see error-handling requirements: "MongoDB unavailable").
MONGODB_SERVER_SELECTION_TIMEOUT_MS = int(
    os.environ.get("MONGODB_SERVER_SELECTION_TIMEOUT_MS", "10000")
)

_DEV_DEFAULT_URI = "mongodb://localhost:27017"


def assert_production_ready(app_env: str, mongodb_uri: str) -> None:
    """Pure decision function (unit-tested directly, mirrors
    `api/main.py::resolve_cors_origins` / `api/dependencies.py::resolve_jwt_secret`):
    refuse to start with APP_ENV=production against an unauthenticated
    and/or unencrypted-in-transit MongoDB connection.

    This cannot and does not verify encryption-AT-REST — that is a
    server-side `mongod`/Atlas configuration this client can't
    inspect from a connection string. See docs/SECURITY_MONGODB.md.
    """
    app_env = (app_env or "development").strip().lower()
    if app_env != "production":
        return

    if mongodb_uri.strip() == _DEV_DEFAULT_URI:
        raise RuntimeError(
            "APP_ENV=production but MONGODB_URI is still the unauthenticated "
            "local development default. Set MONGODB_URI to a production "
            "MongoDB deployment with authentication and TLS enabled "
            "(see docs/SECURITY_MONGODB.md)."
        )

    parsed = urlsplit(mongodb_uri)
    scheme_is_srv = parsed.scheme == "mongodb+srv"
    query = parsed.query.lower()
    tls_requested = scheme_is_srv or "tls=true" in query or "ssl=true" in query
    has_credentials = bool(parsed.username)
    has_auth_source = "authsource=" in query

    if not (has_credentials or has_auth_source):
        raise RuntimeError(
            "APP_ENV=production requires an authenticated MongoDB connection. "
            "MONGODB_URI has no credentials and no authSource — set up a "
            "dedicated least-privilege CipherQ database user and include it "
            "in MONGODB_URI (see docs/SECURITY_MONGODB.md)."
        )
    if not tls_requested:
        raise RuntimeError(
            "APP_ENV=production requires MongoDB connections to use TLS. "
            "Add 'tls=true' to MONGODB_URI (or use a 'mongodb+srv://' Atlas "
            "URI, which implies TLS) — see docs/SECURITY_MONGODB.md."
        )


def _build_client_kwargs() -> dict:
    kwargs: dict = {"serverSelectionTimeoutMS": MONGODB_SERVER_SELECTION_TIMEOUT_MS}
    if MONGODB_TLS_CA_FILE:
        kwargs["tlsCAFile"] = MONGODB_TLS_CA_FILE
    return kwargs


# Fail fast at startup, not on the first incoming request, the same
# way api/dependencies.py::get_jwt_service and api/main.py's CORS
# check already do.
assert_production_ready(os.environ.get("APP_ENV", "development"), MONGODB_URI)

# pymongo connects lazily — constructing MongoClient does not itself
# open a socket or block, so this is safe to do at import time (mirrors
# how `engine = create_engine(...)` worked for the previous
# SQLAlchemy-backed session module).
client: MongoClient = MongoClient(MONGODB_URI, **_build_client_kwargs())
raw_db: Database = client[MONGODB_DATABASE]
# Application-side whole-document encryption is opt-in and fail-closed.
# When enabled, all application reads/writes go through EncryptedDatabase.
db = EncryptedDatabase(raw_db) if encryption_enabled() else raw_db


def get_db() -> Generator[Database, None, None]:
    """FastAPI dependency: yields the MongoDB database handle."""
    yield db


def get_next_id(collection_name: str) -> int:
    """
    Atomically allocate the next integer id for `collection_name`.

    MongoDB documents default to an ObjectId `_id`, but the existing
    API response schemas (`api/schemas.py`) declare id fields as
    plain `int` (e.g. `record_id: int`, `intent_id: int`,
    `PolicyResponse.id: int`) and those schemas are not being changed
    as part of this migration. To keep ids working as ints end to end,
    every collection stores an application-assigned integer `_id`,
    handed out here via a dedicated `counters` collection — the
    standard MongoDB pattern for auto-increment-style ids.

    Self-healing seed: `scripts/migrate_entire_database_to_encrypted.py`
    preserves each document's original integer `_id` when migrating a
    collection into encrypted envelopes, but it never touches the
    `counters` collection. On a freshly migrated database `counters` is
    therefore empty, so the very first `get_next_id()` call for any
    already-populated collection (e.g. `audit_logs`, written on every
    login) would otherwise start again at seq=1 and immediately collide
    with real, pre-existing data — the exact
    `DuplicateKeyError: ... audit_logs index: _id_ dup key: { _id: 1 }`
    seen after enabling whole-document encryption. So: the first time a
    collection's counter is created, seed it from that collection's
    current highest integer `_id` rather than from zero.
    """
    if db.counters.find_one({"_id": collection_name}) is None:
        highest = 0
        for doc in db[collection_name].find({}):
            doc_id = doc.get("_id")
            if isinstance(doc_id, int) and doc_id > highest:
                highest = doc_id
        # $setOnInsert only takes effect if this call is the one that
        # creates the counter doc; if another request wins the race,
        # this is a harmless no-op and the increment below still applies.
        db.counters.update_one(
            {"_id": collection_name},
            {"$setOnInsert": {"seq": highest}},
            upsert=True,
        )

    counter = db.counters.find_one_and_update(
        {"_id": collection_name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return counter["seq"]

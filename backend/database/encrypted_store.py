"""Transparent whole-document AES-256-GCM encryption for CipherQ's MongoDB layer.

This module is intentionally scoped to the database boundary. Application code
continues to read/write ordinary Python dictionaries while MongoDB stores only
an _id plus an authenticated ciphertext envelope.
"""
from __future__ import annotations

import base64
import copy
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from dotenv import load_dotenv

load_dotenv()

from bson import BSON
from bson.binary import Binary
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_MARKER = "CIPHERQ-WHOLE-DOC-v1"
_NONCE_BYTES = 12
_KEY_BYTES = 32
_DEFAULT_KEY_FILE = Path(__file__).with_name(".whole_db_encryption_key")


def _configured_key_path() -> Path:
    """Resolve a configured key path relative to the backend directory.

    This keeps `./database/.whole_db_encryption_key` stable when CipherQ is
    launched from VS Code, the backend directory, or a project-level helper.
    Absolute paths are preserved unchanged.
    """
    configured = os.getenv("CIPHERQ_WHOLE_DB_ENCRYPTION_KEY_FILE")
    if not configured:
        return _DEFAULT_KEY_FILE
    path = Path(configured)
    if path.is_absolute():
        return path
    return Path(__file__).resolve().parent.parent / path


def _key_from_config() -> bytes:
    raw = os.getenv("CIPHERQ_WHOLE_DB_ENCRYPTION_KEY")
    if raw:
        try:
            key = base64.urlsafe_b64decode(raw.encode("ascii"))
        except Exception as exc:
            raise RuntimeError("CIPHERQ_WHOLE_DB_ENCRYPTION_KEY is not valid base64") from exc
        if len(key) != _KEY_BYTES:
            raise RuntimeError("CipherQ whole-database key must decode to exactly 32 bytes")
        return key

    path = _configured_key_path()
    if not path.exists():
        raise RuntimeError(
            "Whole-database encryption is enabled but no encryption key was found. "
            f"Generate one with backend/scripts/generate_whole_db_encryption_key.py "
            f"or set CIPHERQ_WHOLE_DB_ENCRYPTION_KEY_FILE. Expected: {path}"
        )
    try:
        encoded = path.read_text(encoding="utf-8").strip()
        key = base64.urlsafe_b64decode(encoded.encode("ascii"))
    except Exception as exc:
        raise RuntimeError(f"Unable to read CipherQ encryption key: {path}") from exc
    if len(key) != _KEY_BYTES:
        raise RuntimeError("CipherQ whole-database key must decode to exactly 32 bytes")
    return key


def generate_key() -> str:
    """Create and persist a 256-bit key for local development."""
    path = _configured_key_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(f"Key already exists: {path}")
    encoded = base64.urlsafe_b64encode(os.urandom(_KEY_BYTES)).decode("ascii")
    path.write_text(encoded + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return encoded


def encryption_enabled() -> bool:
    return os.getenv("CIPHERQ_WHOLE_DB_ENCRYPTION", "false").strip().lower() in {"1", "true", "yes", "on"}


def strict_enabled() -> bool:
    return os.getenv("CIPHERQ_ENCRYPTION_STRICT", "true").strip().lower() in {"1", "true", "yes", "on"}


def _aad(collection_name: str) -> bytes:
    return f"CipherQ|{_MARKER}|{collection_name}".encode("utf-8")


def encrypt_document(document: dict[str, Any], collection_name: str, key: bytes | None = None) -> dict[str, Any]:
    if not isinstance(document, dict) or "_id" not in document:
        raise ValueError("CipherQ encrypted documents require a MongoDB _id")
    key = key or _key_from_config()
    payload = {k: copy.deepcopy(v) for k, v in document.items() if k != "_id"}
    plaintext = BSON.encode(payload)
    nonce = os.urandom(_NONCE_BYTES)
    sealed = AESGCM(key).encrypt(nonce, plaintext, _aad(collection_name))
    return {
        "_id": document["_id"],
        "_enc": _MARKER,
        "nonce": Binary(nonce),
        "ciphertext": Binary(sealed),
    }


def is_encrypted_document(document: dict[str, Any]) -> bool:
    return isinstance(document, dict) and document.get("_enc") == _MARKER and "nonce" in document and "ciphertext" in document


def decrypt_document(document: dict[str, Any], collection_name: str, key: bytes | None = None) -> dict[str, Any]:
    if not is_encrypted_document(document):
        if strict_enabled():
            raise RuntimeError(f"Plaintext MongoDB document detected in encrypted collection '{collection_name}'")
        return copy.deepcopy(document)
    key = key or _key_from_config()
    try:
        plaintext = AESGCM(key).decrypt(bytes(document["nonce"]), bytes(document["ciphertext"]), _aad(collection_name))
        payload = BSON(plaintext).decode()
    except (InvalidTag, ValueError, TypeError, KeyError) as exc:
        raise RuntimeError(f"CipherQ could not decrypt document in collection '{collection_name}'") from exc
    payload["_id"] = document["_id"]
    return payload


def _get_path(doc: dict[str, Any], path: str) -> Any:
    value: Any = doc
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _set_path(doc: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cur = doc
    for part in parts[:-1]:
        if not isinstance(cur.get(part), dict):
            cur[part] = {}
        cur = cur[part]
    cur[parts[-1]] = copy.deepcopy(value)


def _unset_path(doc: dict[str, Any], path: str) -> None:
    parts = path.split(".")
    cur: Any = doc
    for part in parts[:-1]:
        if not isinstance(cur, dict) or part not in cur:
            return
        cur = cur[part]
    if isinstance(cur, dict):
        cur.pop(parts[-1], None)


class _Missing:
    pass


_MISSING = _Missing()


def _condition(value: Any, exists: bool, expected: Any) -> bool:
    if not isinstance(expected, dict) or not any(str(k).startswith("$") for k in expected):
        return exists and value == expected
    for op, rhs in expected.items():
        if op == "$exists":
            if exists != bool(rhs):
                return False
        elif op == "$ne":
            if exists and value == rhs:
                return False
        elif op == "$in":
            if not exists or value not in rhs:
                return False
        elif op == "$nin":
            if exists and value in rhs:
                return False
        elif op == "$gt":
            if not exists or not value > rhs:
                return False
        elif op == "$gte":
            if not exists or not value >= rhs:
                return False
        elif op == "$lt":
            if not exists or not value < rhs:
                return False
        elif op == "$lte":
            if not exists or not value <= rhs:
                return False
        elif op == "$eq":
            if not exists or value != rhs:
                return False
        elif op == "$regex":
            import re
            if not exists or not isinstance(value, str) or re.search(rhs, value) is None:
                return False
        else:
            raise NotImplementedError(f"CipherQ encrypted query operator not supported: {op}")
    return True


def matches(doc: dict[str, Any], query: dict[str, Any]) -> bool:
    for field, expected in query.items():
        if field == "$and":
            if not all(matches(doc, q) for q in expected):
                return False
            continue
        if field == "$or":
            if not any(matches(doc, q) for q in expected):
                return False
            continue
        if field == "$nor":
            if any(matches(doc, q) for q in expected):
                return False
            continue
        value = _get_path(doc, field)
        if not _condition(None if value is _MISSING else value, value is not _MISSING, expected):
            return False
    return True


def _apply_update(doc: dict[str, Any], update: dict[str, Any], inserting: bool = False) -> dict[str, Any]:
    if not any(str(k).startswith("$") for k in update):
        replacement = copy.deepcopy(update)
        replacement.setdefault("_id", doc["_id"])
        return replacement
    out = copy.deepcopy(doc)
    for op, fields in update.items():
        if op == "$set":
            for path, value in fields.items():
                _set_path(out, path, value)
        elif op == "$unset":
            for path in fields:
                _unset_path(out, path)
        elif op == "$inc":
            for path, amount in fields.items():
                current = _get_path(out, path)
                if current is _MISSING:
                    current = 0
                _set_path(out, path, current + amount)
        elif op == "$setOnInsert":
            # Real MongoDB semantics: $setOnInsert only takes effect when
            # the update performs an insert (upsert creating a new
            # document). On an update that matched an *existing*
            # document it is a documented no-op — it must NOT be treated
            # as an unsupported operator, or every idempotent
            # "upsert queried this per-request" pattern (e.g.
            # MongoDeviceRepository.get_status/claim_owner, called on
            # every session refresh and monitoring/start) raises
            # NotImplementedError as soon as the device/session/etc.
            # already exists — i.e. for every returning user, not new
            # ones. This was the actual cause of the intermittent
            # "Internal Server Error" on existing users; it was never an
            # encryption/decryption failure.
            if inserting:
                for path, value in fields.items():
                    _set_path(out, path, value)
        else:
            raise NotImplementedError(f"CipherQ encrypted update operator not supported: {op}")
    return out


@dataclass
class EncryptedCursor:
    documents: list[dict[str, Any]]

    def sort(self, key_or_list: Any, direction: int | None = None):
        pairs = key_or_list if isinstance(key_or_list, list) else [(key_or_list, direction or 1)]
        for key, order in reversed(pairs):
            self.documents.sort(key=lambda d: (_get_path(d, key) is _MISSING, _get_path(d, key)), reverse=(order < 0))
        return self

    def limit(self, n: int):
        self.documents = self.documents[:n]
        return self

    def skip(self, n: int):
        self.documents = self.documents[n:]
        return self

    def __iter__(self):
        return iter(copy.deepcopy(self.documents))

    def __next__(self):
        return next(iter(self.documents))


class EncryptedCollection:
    def __init__(self, raw_collection, key: bytes | None = None):
        self._raw = raw_collection
        self._key = key
        self.name = raw_collection.name
        # Per-document decrypt cache, keyed by _id and the exact
        # (nonce, ciphertext) currently stored for it. AES-GCM decrypt is
        # the dominant cost of every read once a collection has real
        # volume (measured ~18s to decrypt ~44k audit_logs documents in
        # one call) and every prior find()/find_one()/count_documents()
        # re-decrypted the ENTIRE collection from scratch on every
        # single request — including on every login (get_last_hash) and
        # every Qira assessment (verify_integrity + list_entries, i.e.
        # this cost paid TWICE per assessment). Most of these
        # collections (audit_logs especially) are append-only, so a
        # document decrypted once rarely needs decrypting again.
        # Keying on the actual stored ciphertext (not just _id) makes
        # this self-healing rather than a staleness risk: if a document
        # is ever genuinely changed in place — by this process or any
        # other worker/process/tool touching the same MongoDB — its
        # ciphertext no longer matches the cached fingerprint and it is
        # transparently re-decrypted. No explicit invalidation needed on
        # writes made through this object either, for the same reason.
        self._decrypt_cache: dict[Any, tuple[Any, dict[str, Any]]] = {}

    def _decrypt_cached(self, raw_doc: dict) -> dict[str, Any]:
        doc_id = raw_doc.get("_id")
        fingerprint = (raw_doc.get("nonce"), raw_doc.get("ciphertext"))
        cached = self._decrypt_cache.get(doc_id)
        if cached is not None and cached[0] == fingerprint:
            return cached[1]
        decrypted = decrypt_document(raw_doc, self.name, self._key)
        self._decrypt_cache[doc_id] = (fingerprint, decrypted)
        return decrypted

    def _all(self) -> list[dict[str, Any]]:
        return [self._decrypt_cached(d) for d in self._raw.find({})]

    def find(self, filter: dict | None = None, *args, **kwargs) -> EncryptedCursor:
        filter = filter or {}
        docs = [d for d in self._all() if matches(d, filter)]
        return EncryptedCursor(docs)

    def find_one(self, filter: dict | None = None, *args, **kwargs):
        cursor = self.find(filter or {})

        # Support the subset of PyMongo find_one options used by CipherQ.
        # Whole-document encryption requires matching after decryption, so
        # these operations are intentionally applied to the decrypted cursor.
        sort_spec = kwargs.get("sort")
        if sort_spec is not None:
            cursor.sort(sort_spec)

        skip = kwargs.get("skip")
        if skip:
            cursor.skip(skip)

        limit = kwargs.get("limit")
        if limit:
            cursor.limit(limit)

        for d in cursor:
            return d
        return None

    def count_documents(self, filter: dict | None = None, *args, **kwargs) -> int:
        return len(self.find(filter or {}).documents)

    def insert_one(self, document: dict, *args, **kwargs):
        return self._raw.insert_one(encrypt_document(document, self.name, self._key), *args, **kwargs)

    def insert_many(self, documents: Iterable[dict], *args, **kwargs):
        encrypted = [encrypt_document(d, self.name, self._key) for d in documents]
        return self._raw.insert_many(encrypted, *args, **kwargs)

    def _matching_raw(self, filter: dict) -> list[dict]:
        return [d for d in self._raw.find({}) if matches(self._decrypt_cached(d), filter)]

    def update_one(self, filter: dict, update: dict, upsert: bool = False, *args, **kwargs):
        raw_matches = self._matching_raw(filter)
        if raw_matches:
            raw = raw_matches[0]
            old = decrypt_document(raw, self.name, self._key)
            new = _apply_update(old, update)
            return self._raw.replace_one({"_id": raw["_id"]}, encrypt_document(new, self.name, self._key), *args, **kwargs)
        if upsert:
            base = {k: copy.deepcopy(v) for k, v in filter.items() if not str(k).startswith("$") and not isinstance(v, dict)}
            if "_id" not in base:
                # Let MongoDB generate an ObjectId only if the caller didn't require an integer id.
                from bson import ObjectId
                base["_id"] = ObjectId()
            new = _apply_update(base, update, inserting=True)
            return self._raw.insert_one(encrypt_document(new, self.name, self._key), *args, **kwargs)
        return _UpdateResult(False)

    def update_many(self, filter: dict, update: dict, *args, **kwargs):
        matched = self._matching_raw(filter)
        for raw in matched:
            old = decrypt_document(raw, self.name, self._key)
            new = _apply_update(old, update)
            self._raw.replace_one({"_id": raw["_id"]}, encrypt_document(new, self.name, self._key))
        return _UpdateResult(bool(matched), len(matched))

    def replace_one(self, filter: dict, replacement: dict, *args, **kwargs):
        raw = self._matching_raw(filter)
        if not raw:
            return _UpdateResult(False)
        replacement = copy.deepcopy(replacement)
        replacement.setdefault("_id", raw[0]["_id"])
        return self._raw.replace_one({"_id": raw[0]["_id"]}, encrypt_document(replacement, self.name, self._key), *args, **kwargs)

    def find_one_and_update(self, filter: dict, update: dict, *args, **kwargs):
        from pymongo.collection import ReturnDocument
        raw = self._matching_raw(filter)
        if not raw:
            if kwargs.get("upsert") or "upsert" in kwargs and kwargs["upsert"]:
                self.update_one(filter, update, upsert=True)
                return self.find_one(filter)
            return None
        old = decrypt_document(raw[0], self.name, self._key)
        new = _apply_update(old, update)
        self._raw.replace_one({"_id": raw[0]["_id"]}, encrypt_document(new, self.name, self._key))
        return new if kwargs.get("return_document") == ReturnDocument.AFTER or (args and args[0] == ReturnDocument.AFTER) else old

    def delete_one(self, filter: dict, *args, **kwargs):
        raw = self._matching_raw(filter)
        if not raw:
            return _DeleteResult(0)
        result = self._raw.delete_one({"_id": raw[0]["_id"]}, *args, **kwargs)
        return result

    def delete_many(self, filter: dict | None = None, *args, **kwargs):
        raw = self._matching_raw(filter or {})
        for d in raw:
            self._raw.delete_one({"_id": d["_id"]})
        return _DeleteResult(len(raw))

    def create_index(self, *args, **kwargs):
        # Only _id is safe to index transparently because application fields are ciphertext.
        keys = args[0] if args else kwargs.get("keys")
        if keys in ("_id", [("_id", 1)], [("_id", -1)]):
            return self._raw.create_index(*args, **kwargs)
        raise RuntimeError("Creating indexes on encrypted application fields is not supported by whole-document encryption")


class _UpdateResult:
    def __init__(self, matched: bool, modified_count: int = 0):
        self.matched_count = 1 if matched else 0
        self.modified_count = modified_count if modified_count else (1 if matched else 0)
        self.upserted_id = None


class _DeleteResult:
    def __init__(self, count: int):
        self.deleted_count = count


class EncryptedDatabase:
    """Small Database facade that exposes encrypted collections."""
    def __init__(self, raw_database):
        self._raw = raw_database
        self.name = raw_database.name
        self._key = _key_from_config()

    def __getitem__(self, collection_name: str) -> EncryptedCollection:
        return EncryptedCollection(self._raw[collection_name], self._key)

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return self[name]

    def list_collection_names(self, *args, **kwargs):
        return self._raw.list_collection_names(*args, **kwargs)

    @property
    def client(self):
        return self._raw.client

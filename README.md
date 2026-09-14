# Intent-Bound Quantum Cryptography (IBQC)

A research-quality prototype demonstrating that secure key establishment
alone is insufficient: encryption keys derived from a BB84 quantum
channel are cryptographically bound to a **Cryptographic Intent
Descriptor (CID)** — a structured, deterministic, verifiable
authorization context — so that decryption succeeds only when the
approved operational context matches the original authorization.

See `docs/architecture-design-document.md` for the full design
rationale, including a detailed comparison against the reference
project this repo was inspired by (what was reused, what was
redesigned, and why).

## Status

This is being built incrementally, module by module, in dependency
order. Current state:

- [x] `intent/` — CID schema, canonicalizer, lifecycle state machine, versioning (with unit tests)
- [x] `database/` — MongoDB (PyMongo) document repositories
- [x] `quantum/` — BB84 simulation (adapted from reference project, kept independent)
- [x] `crypto/` — HKDF + AES-256-GCM, `EncryptionService` enforcing the intent-binding claim
- [x] `policy/` — rule engine (6 rules) + risk engine (Low/Medium/High -> action)
- [x] `audit/` — hash-chained, tamper-evident audit log
- [x] `authentication/` — JWT + password hashing + face-auth (identity verification via descriptor distance, never expression)
- [x] `api/` — FastAPI routers: `/api/auth`, `/api/face`, `/api/intent`, `/api/encrypt`, `/api/decrypt`, `/api/audit`, `/api/policies`, `/api/quantum`, `/api/risk`
- [x] `frontend/` — React + Vite + Tailwind. 11 pages: Landing, Login/Register, Dashboard, Create Intent, Intent History, BB84 Simulation, Encrypt, Decrypt, Audit Logs, Policy Management, Visualization
- [ ] Demonstration-scenario integration tests / seed data
- [ ] Final docs pass (sequence/ER diagrams, deployment guide)
## Accounts & roles

The platform has three privilege tiers, defined in `backend/api/rbac.py`:

| Role | How it's created | What it can do |
|---|---|---|
| `USER_LEVEL_1` | Self-registration (default) | Create/submit intents; only ever sees and acts on their **own** records. Cannot approve any intent, including their own. No audit-log read access. |
| `USER_LEVEL_2` | Self-registration (opt-in) | Everything Level 1 can do, plus: sees **all** users' intents, can approve other users' intents (not their own), and can read the audit log. |
| `ADMIN` | Never self-registered — see below | Everything Level 2 can do, plus: bypasses ownership checks anywhere in the app, can approve their own intents, manages user roles (`PUT /api/users/{id}/role`), full audit access. |

### Signing up as a user

`POST /api/auth/register` (and the Register form in the UI) lets the
caller pick their starting tier via an optional `role` field:

```json
{ "username": "...", "email": "...", "password": "...", "role": "USER_LEVEL_2" }
```

- `role` is optional — omit it and the account defaults to `USER_LEVEL_1`.
- The only accepted values are `"USER_LEVEL_1"` and `"USER_LEVEL_2"`. Anything
  else (including `"ADMIN"`) is rejected outright by the request schema —
  self-service admin is not possible through this or any other endpoint.
- An existing `ADMIN` can still change a user's tier after the fact via
  `PUT /api/users/{id}/role`.

### Getting an admin account

Admin is deliberately **not** reachable through the API. The only way to
create one is the out-of-band bootstrap script:

```bash
cd backend
python3 scripts/seed_admin.py
# or with your own credentials:
python3 scripts/seed_admin.py --admin-username myadmin --admin-password "S0meStr0ngP@ss!"
# or a random one-time password, printed once and never stored:
python3 scripts/seed_admin.py --random-admin-password
```

This also seeds a `demo_user` (`USER_LEVEL_1`) unless you pass
`--no-demo-user`. Default bootstrap credentials (change immediately outside
a local demo):

| Field | Value |
|---|---|
| Username | `admin` |
| Password | `AdminSetup#2026` |
| Email | `admin@cipherq.local` |

The script is safe to re-run — it never overwrites an existing user's
password or role.
## Backend setup

This sandbox has no network access, so the code below has been
syntax-checked (`py_compile`) but not executed against real
dependencies. Run it locally:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# run the intent-module unit tests
pytest

# point at a running MongoDB instance (defaults shown below — dev only,
# no auth/TLS/encryption-at-rest; see docs/SECURITY_MONGODB.md for
# production requirements before deploying)
export MONGODB_URI="mongodb://localhost:27017"
export MONGODB_DATABASE="ibqc"

# run the API server
export JWT_SECRET="change-me"
uvicorn api.main:app --reload --port 8000
# interactive API docs at http://localhost:8000/docs
```

## Frontend setup

```bash
cd frontend
npm install
npm run dev
# opens on http://localhost:5173, proxies /api to the backend
```

face-api.js identity-verification models are already included under
`public/models/` (detector + landmarks + recognition — deliberately
*not* the expression model, since this project never classifies
expression). If you swap in a different model set, keep those three.

## Repository layout

```
backend/
  authentication/   # JWT + face-auth (identity/liveness only, no expression signal)
  intent/            # CID schema, canonicalizer, lifecycle, versioning
  quantum/           # BB84 simulation — intentionally independent of every other module
  crypto/            # HKDF derivation + AES-256-GCM, no key ever persisted
  policy/            # policy engine (runs before key derivation) + risk engine
  audit/             # hash-chained, tamper-evident audit log
  database/          # MongoDB (PyMongo) client, document repositories
  api/               # FastAPI routers — thin, no business logic
  tests/
frontend/
  src/
    pages/           # Login, Dashboard, CreateIntent, IntentHistory, BB84Simulation,
                      # Encryption, Decryption, AuditLogs, PolicyManagement, Visualization
docs/
  architecture-design-document.md
  SECURITY_MONGODB.md   # MongoDB auth / TLS / encryption-at-rest / key mgmt / backups
```

## MongoDB security

Local development (`mongodb://localhost:27017`, no auth/TLS) works
unchanged. Deploying with `APP_ENV=production` requires MongoDB
authentication and TLS — the backend fails fast at startup otherwise.
**See `docs/SECURITY_MONGODB.md`** for what's fully implemented
(the client-side production check), what's development-only (the
local default), and what production configuration is required on the
MongoDB side itself (native encryption-at-rest needs MongoDB
Enterprise or a managed deployment like Atlas — it cannot be enabled
on the Community Server this project uses in development, and this
repo does not fake it).


## Local encrypted MongoDB setup — Windows / VS Code

**Current package state:** the existing `ibqc` database is expected to already be migrated to CipherQ whole-document AES-256-GCM encryption. The application must therefore run with the same encryption key that was used for the migration. **Never generate a new key for an existing encrypted database.**

### 1. Open the project in VS Code

Open the extracted `v15` folder. The important folders are:

```text
v15/
  backend/
  frontend/
  docs/
  README.md
```

### 2. Create `backend/.env`

Copy:

```text
backend/.env.example
```

to:

```text
backend/.env
```

For the already-encrypted local database, make sure these values are present:

```env
MONGODB_URI=mongodb://127.0.0.1:27017
MONGODB_DATABASE=ibqc
CIPHERQ_WHOLE_DB_ENCRYPTION=true
CIPHERQ_ENCRYPTION_STRICT=true
CIPHERQ_WHOLE_DB_ENCRYPTION_KEY_FILE=./database/.whole_db_encryption_key
```

Keep the existing key file at:

```text
backend/database/.whole_db_encryption_key
```

If you already have the key from the migration, copy that **same key file** into this location. Do not create another key. The key is deliberately not included in this ZIP.

### 3. Backend setup in the VS Code terminal

Open a terminal in the `v15` folder and run:

```bat
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If `.venv` already exists and dependencies are installed, skip these commands.

### 4. Start the backend

From `v15\backend`:

```bat
.venv\Scripts\activate
python -m uvicorn api.main:app --reload --env-file .env
```

The backend should start at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

The application now also loads `.env` itself at the database boundary, so direct backend scripts and VS Code runs do not accidentally fall back to an unencrypted `Database` object when the process environment was not pre-populated.

### 5. Start the frontend

Open a **second VS Code terminal**:

```bat
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

Vite proxies `/api` requests to the backend on port 8000.

### 6. One-click Windows startup

After one-time setup, you can double-click:

```text
START_CIPHERQ_WINDOWS.bat
```

It opens separate backend and frontend terminals and keeps the encrypted MongoDB configuration enabled.

### 7. First verification after startup

From `v15\backend`, the safest VS Code diagnostic is:

```bat
.venv\Scripts\activate
python scripts\check_local_encryption.py
```

To check one account without printing its sensitive data:

```bat
python scripts\check_local_encryption.py --username yug1
```

For an existing encrypted database, the expected runtime result is:

```text
ENCRYPTION ENABLED: True
DB TYPE: EncryptedDatabase
IS ENCRYPTED DB: True
```

If a username is found, the diagnostic reports only whether basic fields
exist; it never prints the password, password hash, salt, or encryption key.

### 7. First verification after startup

Before testing the UI, open:

```text
http://127.0.0.1:8000/api/health
```

Then test in this order:

1. Register a new user.
2. Complete face enrollment.
3. Complete face verification.
4. Allow the security telemetry/access prompt.
5. Confirm the dashboard opens.
6. Confirm Live Security Monitoring starts.
7. Log out and log back in.
8. Confirm the same user's details are recovered correctly.
9. In MongoDB Compass, confirm application documents still appear as `_id`, `_enc`, `nonce`, and `ciphertext` rather than readable payload fields.

### 8. Important: do not migrate the database again

The encrypted database is already migrated. Do **not** run:

```text
scripts/migrate_entire_database_to_encrypted.py
```

again unless you intentionally restore a plaintext backup and are performing a new migration.

Do **not** run the key-generation script for the existing `ibqc` database. Losing/replacing the current key would make the existing encrypted payloads unreadable.

### 9. What the encryption layer does

CipherQ uses whole-document application-side encryption at the MongoDB boundary. The application works with normal decrypted Python documents, while MongoDB stores an authenticated AES-256-GCM envelope:

```text
Application
    ↓
EncryptedDatabase
    ↓ AES-256-GCM
MongoDB
    ↓
_id + _enc + nonce + ciphertext
```

The database wrapper decrypts documents before repositories/services consume them. This is why users can still see their normal account information in the application while MongoDB Compass does not expose the plaintext payload.

### 10. If login says "invalid username or password"

Do not immediately reset the password or migrate the database. Check the backend terminal first. The intended flow is:

```text
POST /api/auth/register
        ↓
Encrypted users document written to ibqc.users
        ↓
POST /api/auth/login
        ↓
Encrypted users document decrypted by EncryptedDatabase
        ↓
PBKDF2 password verification
        ↓
JWT/session
        ↓
Face verification
        ↓
Continuous monitoring
```

A login failure after successful registration should be debugged by tracing that exact chain. The repository must never be changed to bypass encryption.

### 11. If Live Monitoring does not start

Live monitoring is intentionally downstream of authentication:

```text
Login
  ↓
Face verification
  ↓
Authorized session
  ↓
Monitoring session
  ↓
Camera + face checks
  ↓
Heartbeat
  ↓
Encrypted monitoring events in MongoDB
```

Fix authentication/session errors first. Then inspect `/api/monitoring/*` requests in the browser Network tab and the backend terminal.

### 12. Security rules

- Never commit `backend/.env`.
- Never commit `backend/database/.whole_db_encryption_key`.
- Never put the encryption key in the frontend.
- Never print the key, password, or password hash in logs.
- Never disable strict encryption just to make a feature work.
- Never create a second plaintext database as a workaround.
- Keep the external pre-migration backup until the encrypted application has been fully regression-tested.

For the distinction between application-side encryption and MongoDB native encryption-at-rest, see `docs/SECURITY_MONGODB.md` and `docs/LOCAL_APPLICATION_ENCRYPTION.md`.

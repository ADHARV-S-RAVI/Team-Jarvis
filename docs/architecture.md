# Q-SHIELD — System Architecture

## 1. High-Level Overview
Q-SHIELD separates the **official Track 4 CLI adapter** (`track4_service.py`) from the **FastAPI Control Plane** (`backend/app/`) and the **React Operator Console** (`frontend/src/`), all backed by SQLite + Alembic migrations and a local key store.

```text
+-----------------------+        HTTP/JSON        +------------------------------+
|  React 18 + Vite UI   | <---------------------> |   FastAPI Control Plane      |
|  (16 pages, 14 demos) |    localhost:5173->8000 |   backend/app/main.py        |
+-----------------------+                         +--------------+---------------+
                                                                 |
+-----------------------+                                        v
| Official Track 4 CLI  |   stdin/stdout JSON     +------------------------------+
|   track4_service.py   | <---------------------> |  9-Step Fail-Closed Authz    |
+-----------------------+                         |  Crypto / Vault / Audit /    |
                                                  |  Nodes / Detector / Msg      |
                                                  +--------------+---------------+
                                                                 |
                                                  +--------------+---------------+
                                                  |  SQLite (WAL) + .qshield_keys|
                                                  +------------------------------+
```

## 2. Backend Modules (`backend/app/`)
- `api/v1/router.py`: REST API surface (66 endpoints across all 12 goal areas).
- `policy/authz.py`: 9-step fail-closed authorization pipeline (`AuthzRequest` -> `ALLOW`/`DENY`).
- `crypto/provider.py`: Vetted primitives (`ML-KEM-768`, `AES-256-GCM`, `HKDF-SHA-256`, `HMAC-SHA-256`, `SHA-256`).
- `vault/`: Encrypted resource storage with per-resource DEKs wrapped by KEK.
- `devices/` & `services/foundation_service.py`: Identity, device lifecycle (suspend/restore/revoke/replace), session management, and lost-device incidents.
- `nodes/`: **In-process simulated node cluster** (3–7 nodes) with partition, latency, reconciliation, and convergence tracking.
- `keys/` & `recovery/`: 4-phase key rotation (`PREPARE` -> `BACKUP` -> `PROPAGATE` -> `COMMIT/RETIRE`), crash-safe rotation journal (7-point crash matrix), and signed backups.
- `audit/`: Append-only hash-chained audit ledger (`prev_hash`, `entry_hash`, HMAC) with tamper detection and secret redaction.
- `detector/`: Deterministic, zero-ML rule engine for privilege escalation, lateral movement graphs, and clock-skew reordering.
- `messaging/`: AEAD messaging with recipient-bound AAD, durable replay ledger, loss/reordering recovery, and peer-bound session resumption.

## 3. Frontend Structure (`frontend/src/`)
- React 18, TypeScript, Vite, Tailwind CSS, TanStack Query, React Router v7, Recharts.
- 16 operational routes (`/`, `/login`, `/overview`, `/identities`, `/devices`, `/vault`, `/keys`, `/nodes`, `/incidents`, `/detector`, `/messaging`, `/audit`, `/scenarios`, `/benchmarks`, `/scorecard`, `/settings`).
- Zero tokens or plaintext persisted in `localStorage`.

## 4. Database & Persistence
- SQLite with SQLAlchemy 2 and Alembic (`0001` through `0007` migrations).
- Stores identities, devices, sessions, vault ciphertext, key metadata, revocations, simulated node state, rotation journals, backup manifests, audit events, detector events/alerts, and messaging/replay records.
- Secret key material is separated from SQLite in `.qshield_keys/` (`master_kek.key`, `key_versions.json`).

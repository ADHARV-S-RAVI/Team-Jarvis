# Q-SHIELD — Backend Foundation (Stage 2)

**Runtime:** Python `3.12.3`  
**Stack:** FastAPI `0.165.0`, Pydantic `2.14.4`, pydantic-settings `2.16.3`, SQLAlchemy `2.1.9`, Alembic `1.20.1`, SQLite (WAL + Foreign Keys), Uvicorn `0.54.0`, HTTPX `0.28.1`  
**Status:** Stage 2 Backend Foundation & 9-Step Zero-Trust Authorization Engine **PASS**

---

## 1. Backend Structure (`backend/`)

```text
backend/
├── alembic.ini
├── alembic/
│   ├── env.py
│   ├── script.py.mako
│   └── versions/
│       └── 0001_initial_foundation.py
├── app/
│   ├── __init__.py
│   ├── config.py                   # Environment-based Settings (QSHIELD_*)
│   ├── main.py                     # FastAPI app factory, correlation ID middleware, safe error handlers
│   ├── api/v1/router.py            # Versioned /api/v1 endpoints
│   ├── db/
│   │   ├── session.py              # SQLite engine (PRAGMA foreign_keys=ON, WAL, busy_timeout=5000)
│   │   └── models.py               # 9 foundational SQLAlchemy 2 ORM models
│   ├── policy/
│   │   └── authz.py                # 9-step fail-closed zero-trust authorization engine
│   ├── schemas/foundation.py       # Typed Pydantic v2 request/response schemas
│   └── services/foundation_service.py # Domain services + foundational audit recording
└── tests/
    ├── test_authz_pipeline.py      # 11 unit tests for all 9 authz steps + fail-closed DB error
    └── test_api_and_db.py          # 3 integration tests for Alembic, SQLite pragmas, API & persistence
```

---

## 2. Database Schema (`0001_initial_foundation`)

- `actors` — Synthetic identities (`id`, `display_label`, `role`, `enabled`, `created_at`)
- `role_permissions` — Server-side RBAC mapping (`role`, `permission`)
- `devices` — Enrolled devices (`id`, `owner_actor_id`, `credential_fingerprint`, `state`, `state_version`, `enrolled_at`, `last_seen_at`, `revocation_reason`)
- `sessions` — Peer-bound opaque sessions storing SHA-256 `token_hash` (`id`, `token_hash`, `actor_id`, `device_id`, `peer_id`, `issued_at`, `expires_at`, `revoked_at`, `version`)
- `key_metadata` — Minimal key-version state for Step 8 authorization (`id`, `version`, `algorithm`, `state`, timestamps)
- `resources` — Protected synthetic assets (`id`, `owner_actor_id`, `content_ref`, `key_version`, `state`, `created_at`)
- `revocation_tombstones` — Durable revocation records (`id`, `subject_type`, `subject_id`, `epoch`, `reason`, `created_at`)
- `incident_policy_denials` — Active incident/policy deny rules for Step 9 (`id`, `subject_type`, `subject_id`, `active`, `reason`, `created_at`)
- `audit_events` — Foundational structured audit events (`event_id`, `sequence`, `timestamp`, `actor_id`, `action`, `target`, `decision`, `reason`, `correlation_id`, `metadata_json`, `prev_hash`, `event_hash`)

---

## 3. Nine-Step Zero-Trust Authorization Pipeline (`backend/app/policy/authz.py`)

Executed server-side in strict order; any failure or unexpected exception **fails closed** (`DENY`):
1. **Request Validity:** Non-empty `actor_id`, `session_id`, `device_id`, `resource_id`, `action`.
2. **Identity Active:** `Actor` exists, `enabled=True`, and no `actor` `RevocationTombstone`.
3. **Session Bound:** `AuthSession` exists, `session.actor_id == actor.id`, optional `session_token` SHA-256 matches `token_hash`, optional `peer_id` matches `session.peer_id`.
4. **Session Active:** `session.revoked_at is None`, no `session` tombstone, and `expires_at > now`.
5. **Device Trusted:** `Device` exists, `owner_actor_id == actor.id`, `session.device_id == device.id`, `state == "TRUSTED"`, no `device` tombstone.
6. **Permission & Ownership:** `RolePermission` grants `action` for `actor.role`, and owner-scoped actions (`resource:read/write/delete`) enforce `resource.owner_actor_id == actor.id` (prevents cross-user IDOR).
7. **Resource Active:** `Resource` exists and `state == "ACTIVE"`.
8. **Key Version Active:** `KeyMetadata` for `resource.key_version` exists, `state in {"ACTIVE", "ACTIVE_NEW"}`, and no `key` tombstone.
9. **Incident/Policy Clear:** No active `IncidentPolicyDenial` for the actor, device, resource, or key.

---

## 4. API Endpoints (`/api/v1`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Service and SQLite database health check |
| `POST` | `/api/v1/identities` | Register synthetic identity |
| `GET` | `/api/v1/identities/{actor_id}` | Lookup identity |
| `POST` | `/api/v1/devices` | Register device for an identity |
| `GET` | `/api/v1/devices/{device_id}` | Lookup device |
| `POST` | `/api/v1/sessions` | Issue actor/device/peer-bound session (returns raw token once; stores SHA-256 hash) |
| `POST` | `/api/v1/sessions/validate` | Validate session token, binding, expiry, and revocation |
| `POST` | `/api/v1/resources` | Register protected asset |
| `GET` | `/api/v1/resources/{resource_id}` | Authorized asset lookup (enforces 9-step pipeline) |
| `POST` | `/api/v1/policy/evaluate` | Evaluate 9-step authorization decision |
| `POST` | `/api/v1/revocations` | Persist revocation tombstone and update target state |
| `GET` | `/api/v1/revocations/{subject_type}/{subject_id}` | Lookup revocation status |

---

## 5. Run & Verification Commands

- **Run Migrations:** `py -3.12 -m alembic -c backend/alembic.ini upgrade head`
- **Start Server:** `py -3.12 -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000`
- **Run Backend Tests:** `py -3.12 -m pytest -v backend/tests/` (**14 passed in 5.43s**)
- **Adapter Regression:** `py -3.12 -m pytest -v tests/adapter/test_track4_service.py` (**9 passed in 8.72s**)
- **Official Validator:** `py -3.12 validate.py --entry "../../track4_service.py"` (**Exit 0, 21/21 checks PASS**)

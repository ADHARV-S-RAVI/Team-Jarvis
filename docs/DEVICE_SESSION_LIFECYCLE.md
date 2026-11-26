# Q-SHIELD — Device Lifecycle, Sessions & Lost-Device Workflow (Stage 4)

**Runtime:** Python `3.12.3`  
**Status:** **PASS** (`G3: PASS`; 25/25 backend tests pass)

---

## 1. Device Lifecycle (`backend/app/devices/service.py`)

- **States:** `PENDING`, `TRUSTED`, `SUSPENDED`, `REVOKED`.
- **Invariants Enforced:**
  - Enrolment rejects any `credential_fingerprint` previously associated with a `REVOKED` device.
  - `suspend_device` and `restore_device` require `Security Operator` or `Admin` role.
  - `restore_device` only transitions `SUSPENDED -> TRUSTED` and strictly **forbids** reactivating any `REVOKED` or tombstoned device.
  - `revoke_device` commits a `RevocationTombstone("device", device_id)`, sets `state="REVOKED"`, increments `state_version`, and immediately revokes all active `AuthSession` rows bound to that device.
  - `enrol_replacement_device` verifies ownership and `REVOKED` status of the lost device, rejects reusing the old credential fingerprint, and enrols the new device without restoring trust to the old device.

---

## 2. Session Lifecycle (`backend/app/services/foundation_service.py`)

- **Binding:** Sessions store SHA-256 `token_hash` (never raw tokens) and bind `actor_id`, `device_id`, and `peer_id`.
- **Immediate Invalidation (`POST /api/v1/sessions/{session_id}/revoke`):** Sets `revoked_at`, increments `version`, and commits a `RevocationTombstone("session", session_id)` so subsequent requests fail closed immediately.
- **Anti-Inheritance:** Step 3 of `evaluate_authorization()` rejects any attempt by a different identity or peer to reuse an existing `session_id`.

---

## 3. Lost-Device Incident Workflow (`POST /api/v1/incidents/lost-device`)

1. Verifies operator identity (`Security Operator` / `Admin`), enabled status, and explicit `confirmed=True`.
2. Durably revokes the device, commits `RevocationTombstone`, and invalidates active sessions before returning.
3. Invokes `NodePropagationBoundary` (default `PendingStage5NodeBoundary`, ready for Stage 5 multi-node simulator).
4. Creates `Incident` (`LOST_DEVICE`) and `IncidentReceipt` linked to the `AuditEvent` ID (`audit_ref`).

---

## 4. Database & API Changes

- **Migration (`0003_incidents_and_device_lifecycle`):** Added `incidents` and `incident_receipts` tables.
- **New `/api/v1` Endpoints:**
  - `POST /api/v1/devices/enroll`
  - `POST /api/v1/devices/{device_id}/suspend`
  - `POST /api/v1/devices/{device_id}/restore`
  - `POST /api/v1/devices/{device_id}/revoke`
  - `POST /api/v1/devices/{device_id}/replace`
  - `POST /api/v1/sessions/{session_id}/revoke`
  - `POST /api/v1/incidents/lost-device`
  - `GET /api/v1/incidents/{incident_id}`
  - `GET /api/v1/incidents/{incident_id}/receipt`

---

## 5. Known Limitations & Verification Results

- **Node Propagation:** `PendingStage5NodeBoundary` records `PENDING_STAGE_5_SIMULATOR` (`propagated_nodes: 0`) until Stage 5 implements the 3–7 node simulator.
- **Backend Tests:** `py -3.12 -m pytest -v backend/tests/` -> **25 passed in 8.25s** (`exit=0`).
- **Alembic:** `upgrade head` -> **exit=0** (`0003_incidents_and_device_lifecycle`).
- **Adapter & Official Validator:** **9/9 pytest PASS** (`exit=0`), **21/21 `validate.py` checks PASS** (`exit=0`).

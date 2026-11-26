# Q-SHIELD — Crash Recovery & Backup Integrity (Stage 6)

**Runtime:** Python `3.12.3`  
**Status:** **PASS** (`G5: PASS`; 37/37 backend tests pass)

---

## 1. Durable Rotation Journal (`backend/app/recovery/service.py`)

- **Table (`rotation_journal`):** Persists `operation_id`, `previous_version`, `proposed_version`, `phase`, `committed` flag, `retire_policy`, `actor_id`, `reason`, `integrity_hash` (SHA-256 over canonical fields), timestamps, and `evidence_refs_json`.
- **7 Crash Injection Points:** `after_prepare`, `after_backup`, `after_node_partial_ack`, `before_commit`, `immediately_after_commit`, `during_retirement`, `after_revocation_tombstone`.
- **Recovery Semantics (`recover_rotation_journal`):**
  - Verifies `integrity_hash` before any state mutation (corrupted journals fail closed).
  - **Idempotent:** Re-running recovery on `RECOVERED_PRE_COMMIT`, `RECOVERED_POST_COMMIT`, or `COMPLETED` returns `IDEMPOTENT_ALREADY_RECOVERED`.
  - **Pre-commit (`committed=False`):** Restores `previous_version` to `ACTIVE` unless superseded by a revocation tombstone (in which case it fails closed and keeps the key revoked).
  - **Post-commit (`committed=True`):** Preserves `proposed_version` as `ACTIVE_NEW`, enforces `retire_policy` (`RETIRED`/`REVOKED`) on `previous_version`, and reconciles simulated nodes.

---

## 2. Backup Integrity & Verified Restore (`backend/app/backups/service.py`)

- **Manifest (`backup_manifests`):** Stores `backup_epoch`, `active_key_version`, `key_ids_json`, `manifest_sha256`, `hmac_hex` (HMAC-SHA-256 keyed by HKDF purpose `qshield:backup-manifest-auth`), and canonical `payload_json`.
- **Negative Verification Checks (`verify_backup_manifest`):**
  - Rejects incomplete manifests (`BACKUP_INCOMPLETE`).
  - Rejects byte-tampered payloads (`BACKUP_TAMPERED_DIGEST`).
  - Rejects wrong-key/forged HMAC (`BACKUP_INVALID_HMAC_OR_WRONG_KEY`).
  - Rejects stale backups (`BACKUP_STALE_REVOCATION_EPOCH`, `BACKUP_STALE_KEY_VERSION`).
- **Safe Restore (`restore_backup_manifest`):** Never restores unverified material, is idempotent on duplicate restore, and never reactivates `REVOKED` or `COMPROMISED` keys.

---

## 3. Database & API Changes

- **Migration (`0005_rotation_journal_and_backups`):** Added `rotation_journal` and `backup_manifests`.
- **New `/api/v1` Endpoints:**
  - `POST /api/v1/keys/rotate/journaled`
  - `POST /api/v1/keys/recover/{operation_id}`
  - `POST /api/v1/keys/backups/create`
  - `POST /api/v1/keys/backups/verify`
  - `POST /api/v1/keys/backups/restore`

---

## 4. Limitations & Verification Results

- **SQLite Limit:** Single-host ACID durability only, not distributed consensus.
- **Backend Tests:** `py -3.12 -m pytest -v backend/tests/` -> **37 passed** (`exit=0`).
- **Alembic:** `upgrade head` -> **exit=0** (`0005_rotation_journal_and_backups`).
- **Adapter & Official Validator:** **9/9 pytest PASS** (`exit=0`), **21/21 `validate.py` checks PASS** (`exit=0`).

# Q-SHIELD — Test Results

## Stage 1 — Official Toolkit Validator & Adapter Tests (Python 3.12.3)
**Date:** 2026-11-26  
**Environment:** Python `3.12.3` (`C:\Users\adhar\AppData\Local\Programs\Python\Python312\python.exe`), `pqcrypto==0.4.0`, `pytest==9.2.0`  
**Toolkit Commit:** `8901dfbdbfe048853e0bfa25b60583d1e6617a63` (`v1.0.0`)

---

### 1. Official Organizer Validator
- **Command:** `Push-Location tools/Track-4-Toolkit; py -3.12 validate.py --entry "../../track4_service.py"`
- **Exit Code:** `0` (`PASS`)
- **Output Summary:** All 21 checks passed (`Local scenario passed.`):
  - `PASS [format] clean setup`
  - `PASS [setup] clean setup`
  - `PASS [format] owner before device loss` / `PASS [behavior] owner before device loss`
  - `PASS [format] peer before device loss` / `PASS [behavior] peer before device loss`
  - `PASS [format] wrong owner` / `PASS [behavior] wrong owner`
  - `PASS [format] revoke lost-device owner`
  - `PASS [format] owner after revocation` / `PASS [behavior] owner after revocation`
  - `PASS [format] audit revoked read` / `PASS [behavior] audit revoked read`
  - `PASS [format] unaffected peer` / `PASS [behavior] unaffected peer`
  - `PASS [format] revocation persists across processes` / `PASS [behavior] revocation persists across processes`
  - `PASS [format] fresh rerun setup` / `PASS [setup] fresh rerun setup`
  - `PASS [format] fresh rerun owner` / `PASS [behavior] fresh rerun owner`
  - `PASS [behavior] fake key stays out of output`

---

### 2. Independent Process-Level Adapter Tests (`pytest`)
- **Command:** `py -3.12 -m pytest -v tests/adapter/test_track4_service.py`
- **Exit Code:** `0`
- **Result:** **9 passed, 0 failed, 0 skipped** in `4.84s`

| Test Case | Scope Verified | Status |
| :--- | :--- | :--- |
| `test_setup_and_reset_persists_across_processes` | Durable `setup`, cross-process `read`, state reset | PASS |
| `test_owner_and_peer_isolation_and_wrong_owner_deny` | Owner & peer read, wrong-owner deny, zero leakage | PASS |
| `test_disabled_actor_denied` | `disabled` actor denied on `read` | PASS |
| `test_revoke_persists_across_processes_and_preserves_peer` | `revoke` persistence across fresh processes; peer unaffected | PASS |
| `test_audit_correlation_and_boundary_sanitization` | Exact `request_id` correlation & CR/LF boundary sanitization | PASS |
| `test_protected_read_ml_kem_768_interop_and_deny` | `pqcrypto` ML-KEM-768 encaps/decaps + HMAC-SHA-256 `proof` interop + deny | PASS |
| `test_protected_read_rejects_malformed_key_safely` | Malformed Base64 & wrong key length rejected; stderr diagnostics only | PASS |
| `test_invalid_json_unknown_op_and_missing_fields` | Malformed JSON, non-object JSON, unknown op, missing fields | PASS |
| `test_default_os_temp_state_dir_fallback` | OS temp directory fallback when `TRACK4_STATE_DIR` is unset | PASS |

# Q-SHIELD — Toolkit Adapter Implementation (Stage 1)

**Entry Point:** `track4_service.py` (repository root)  
**Official Toolkit Reference:** `tools/Track-4-Toolkit/` (`https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit`, commit `8901dfbdbfe048853e0bfa25b60583d1e6617a63`, `v1.0.0`)  
**Status:** Verified against official `docs/adapter-v1.md` and `validate.py` under Python `3.12.3` (`PASS`).

---

## 1. Architecture & Process Contract

`track4_service.py` is a standalone Python CLI process with zero dependencies on `backend/` or `frontend/`:
- **Input:** Reads one UTF-8 JSON object from `stdin` to EOF.
- **Output:** Writes exactly one compact JSON object to `stdout` (`allow_nan=False`, `\n`-terminated).
- **Diagnostics:** Sanitized diagnostic messages (control characters stripped, capped at 256 chars) are written exclusively to `stderr`.
- **State Persistence:** `AdapterStateStore` resolves `TRACK4_STATE_DIR` if set, otherwise `<OS temp>/qshield_track4_state/adapter_state.json`. Writes use `tempfile.mkstemp` + `os.fsync` + `os.replace` so mutations are atomic and durable before acknowledgment.
- **Business Logic:** `Track4AdapterService` handles `setup`, `read`, `revoke`, `audit`, and `protected_read`.

---

## 2. Official JSON Contract (`docs/adapter-v1.md`)

### 2.1 `setup`
- **Request:** `{"op": "setup", "owners": {"<asset>": "<actor>"}, "contents": {"<asset>": "<body>"}, "disabled": ["<actor>"], "key_material": "<synthetic_value>"}` (also accepts `disabled_actors` as fallback).
- **Response:** `{"ready": true}`

### 2.2 `read`
- **Request:** `{"op": "read", "actor": "<actor>", "asset": "<asset>", "request_id": "<id>"}`
- **Response (Allow):** `{"decision": "allow", "request_id": "<id>", "asset": "<asset>", "body": "<exact_stored_body>"}`
- **Response (Deny):** `{"decision": "deny"}` (no body, snippet, or content-bearing metadata)

### 2.3 `revoke`
- **Request:** `{"op": "revoke", "actor": "<actor>", "request_id": "<id> (optional)"}`
- **Response:** `{"status": "revoked", "actor": "<actor>", "revoked": true}`

### 2.4 `audit`
- **Request:** `{"op": "audit", "request_id": "<id>"}`
- **Response (Found):** `{"found": true, "request_id": "<id>", "decision": "<allow|deny|revoked>", "actor": "<sanitized_actor>", "op": "<op>"}`
- **Response (Not Found):** `{"found": false, "request_id": "<id>", "decision": "unknown"}`

### 2.5 `protected_read`
- **Request:** `{"op": "protected_read", "actor": "<actor>", "asset": "<asset>", "challenge": "<utf8_str>", "public_key": "<base64_ml_kem_768_pk>", "request_id": "<id> (optional)"}`
- **Response (Allow):** `{"decision": "allow", "ciphertext": "<base64_ct>", "proof": "<lowercase_hex_hmac_sha256>", "request_id": "<id> (if provided)"}`
  - Uses `pqcrypto.kem.ml_kem_768.encrypt(pk_bytes)` (`PUBLIC_KEY_SIZE = 1184`, `CIPHERTEXT_SIZE = 1088`, `PLAINTEXT_SIZE = 32`).
  - Computes `HMAC-SHA-256(shared_secret, UTF8(challenge + exact_stored_body))` with no separator.
  - Shared secret is deleted immediately and never logged or returned.
- **Response (Deny):** `{"decision": "deny"}`

### 2.6 Structured Errors
- `{"error": "invalid_json" | "unknown_operation" | "missing_field" | "invalid_field" | "not_initialized" | "invalid_public_key" | "internal_error", "message": "..."}`

---

## 3. Verified Runtime & Dependencies
- **Python:** `3.12.3` (matches official judging runtime `3.12`)
- **Cryptography:** `pqcrypto==0.4.0` (`pqcrypto.kem.ml_kem_768`), Python stdlib `hmac` / `hashlib` / `base64`.
- **Testing:** `pytest==9.2.0`
- **Remaining Limitations:** Local `validate.py` tests lost-device functional/format/leakage checks only (it explicitly notes that cryptography and latency are not tested by the local validator; `protected_read` ML-KEM-768/HMAC interoperability is verified by `tests/adapter/test_track4_service.py` and will also be checked by the organizer's worker).

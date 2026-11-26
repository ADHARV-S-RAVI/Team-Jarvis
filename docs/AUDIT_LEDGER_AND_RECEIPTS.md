# Q-SHIELD — Append-Only Audit Ledger & Proof-Carrying Receipts (Stage 7)

**Runtime:** Python `3.12.3`  
**Status:** **PASS** (`G6: PASS`; 39/39 backend tests pass)

---

## 1. Canonical Serialization & Hash Chain (`backend/app/audit/service.py`)

- **Canonical Version:** `v1` (`UTF-8`, `json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`).
- **Genesis Value:** `"GENESIS"`.
- **Hash Algorithm:** `SHA-256(prev_hash || canonical_event_bytes)`.
- **Sequence Monotonicity:** Serialized via `_AUDIT_LOCK` (`threading.RLock`) so concurrent requests produce strictly monotonic `sequence` numbers.

---

## 2. Boundary Protection & Secret Redaction

- **Control-Character Normalization:** `sanitize_text()` replaces `[\x00-\x1f\x7f]` (CR, LF, null, control chars) with `_` and caps length at `256` characters (`64` for `actor_id`/`action`/`correlation_id`, `128` for `target`/`reason`).
- **One Event Per Record:** Structured JSON storage in `audit_events`; user-supplied text cannot forge `actor_id`, `action`, or inject a second event.
- **Secret Redaction:** `sanitize_metadata()` replaces values for sensitive keys (`token`, `session_token`, `secret`, `shared_secret`, `private_key`, `key_material`, `plaintext`, `password`, `dek`, `kek`, `master_key`) with `"[REDACTED]"`.

---

## 3. Chain Verifier (`verify_audit_records`)

Detects all required integrity violations:
- **Modification & Actor Mutation:** Recomputes canonical SHA-256 hash (`EVENT_HASH_MISMATCH_MODIFIED`).
- **Deletion & Reordering:** Checks monotonic sequence (`SEQUENCE_GAP_OR_REORDER`) and `prev_hash` linkage (`BROKEN_PREV_HASH_LINK`).
- **Boundary/Log Injection:** Scans stored fields for unescaped control characters (`BOUNDARY_INJECTION_IN_*`).

---

## 4. API Endpoints (`/api/v1`)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/audit/events` | Searchable audit events (`actor_id`, `action`, `decision`, `correlation_id`) |
| `GET` | `/api/v1/audit/events/{event_id}` | Single audit event detail |
| `POST` | `/api/v1/audit/verify` | Full persisted hash-chain verification |
| `GET` | `/api/v1/audit/timeline/{correlation_id}` | Sequence-ordered correlation timeline |
| `GET` | `/api/v1/audit/export` | Sanitized JSON export with verification summary |
| `POST` | `/api/v1/audit/tamper-demo` | Non-destructive in-memory tamper detection demo |
| `GET` | `/api/v1/incidents/{incident_id}/verify` | Verify `IncidentReceipt.audit_ref` against verified audit chain |

---

## 5. Trust & Anchoring Limitations

- **ML-DSA Checkpoints:** Deferred (`ml_dsa_checkpoint_status: "DEFERRED_NOT_IMPLEMENTED"`). Signatures are not faked.
- **Anchoring Limit:** A local SHA-256 hash chain alone cannot defeat an attacker who controls both the SQLite storage and the signing/application host.

---

## 6. Verification Results (Python `3.12.3`)

- `py -3.12 -m pytest -v backend/tests/`: **39 passed in 18.02s** (`exit=0`).
- `py -3.12 -m alembic -c backend/alembic.ini upgrade head`: **exit=0**.
- `py -3.12 -m pytest -v tests/adapter/test_track4_service.py`: **9 passed in 4.54s** (`exit=0`).
- `py -3.12 validate.py --entry "../../track4_service.py"`: **Local scenario passed** (**21/21 checks PASS**, `exit=0`).

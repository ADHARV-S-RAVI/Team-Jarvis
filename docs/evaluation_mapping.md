# Q-SHIELD — Evaluation Mapping (Yugaantar DevForge Track 4)

This document maps Q-SHIELD's verified implementation, tests, and evidence to the six Track 4 evaluation criteria. Automated checks below verify Q-SHIELD's implemented controls and do not guarantee organizer scores.

---

## 1. Security Correctness (25 Points)
1. **Evaluates:** Fail-closed authorization, cryptographic integrity, resistance to IDOR/tampering/replay, and salted authentication.
2. **Implementation:** 9-step fail-closed policy gate, salted `scrypt` password hashing (`hmac.compare_digest`) with authorization and rate limiting, AES-256-GCM AEAD with AAD binding, ML-KEM-768 adapter interoperability, and SHA-256 hash-chained audit logs.
3. **Source Paths:** `backend/app/policy/authz.py`, `backend/app/services/foundation_service.py`, `backend/app/crypto/provider.py`, `backend/app/vault/service.py`, `backend/app/messaging/service.py`, `track4_service.py`.
4. **Tests:** `backend/tests/test_authz_pipeline.py`, `backend/tests/test_crypto_and_vault.py`, `backend/tests/test_password_auth.py`, `tests/adapter/test_track4_service.py`.
5. **Evidence:** `reports/security_assessment/report.json`, `reports/security_assessment/independent_summary.md`, `reports/evidence/validator_output.txt`.
6. **Reproduction:**
   - `py -3.12 -m pytest backend/tests/ -v`
   - `cd tools/Track-4-Toolkit && py -3.12 validate.py --entry "../../track4_service.py"`
7. **Limitations:** `forward_secrecy` is `NOT ESTABLISHED`; `ML-DSA` is `NOT IMPLEMENTED`; `KeyMaterialStore` is a local dev store, not a hardware HSM.

---

## 2. Live / Automated Security Assessment (25 Points)
1. **Evaluates:** How security controls behave under automated adversarial probing, negative tests, and live verification.
2. **How Findings Are Detected, Recorded & Handled:**
   - `scripts/run_security_assessment.py` (`SEC-01`..`SEC-18`) and `scripts/run_independent_verification.py` (`IND-01`..`IND-12`) spin up isolated temporary SQLite databases migrated via `alembic upgrade head`, execute live adversarial requests through FastAPI `TestClient`, inspect persisted DB/audit state, and write structured JSON + Markdown reports.
   - During independent verification, three authentication vulnerabilities (`VULN-01` unauthenticated password takeover, `VULN-02` missing login rate limiting, `VULN-03` stale sessions on password change) were detected, documented in `docs/INDEPENDENT_SECURITY_VERIFICATION.md`, fixed, and covered by `backend/tests/test_password_auth.py`.
3. **Source Paths:** `scripts/run_security_assessment.py`, `scripts/run_independent_verification.py`, `backend/tests/test_password_auth.py`.
4. **Evidence:** `reports/security_assessment/summary.md`, `reports/security_assessment/independent_summary.md`, `docs/INDEPENDENT_SECURITY_VERIFICATION.md`.
5. **Reproduction:**
   - `py -3.12 scripts/run_security_assessment.py`
   - `py -3.12 scripts/run_independent_verification.py`
6. **Limitations:** Automated WebAuthn tests use synthetic P-256 fixtures rather than physical Windows Hello hardware.

---

## 3. Functionality & Reliability (20 Points)
1. **Evaluates:** End-to-end operation, enforcement of security controls, crash/disruption recovery, and verifiable outcomes.
2. **Explicit Operational Mapping:**
   - **Normal Operation:** Identity/device enrolment, session creation, encrypted vault read/write, and Data Verification Lab chunked uploads (`backend/app/devices/`, `backend/app/vault/`, `backend/app/datalab/`).
   - **Security Controls:** Lost-device revocation, key rotation with zero-grace cutoff, replay rejection, and FIM baseline scanning (`backend/app/keys/`, `backend/app/messaging/`, `backend/app/integrity/`).
   - **Recovery After Disruption:** 7-point crash-injection rotation journal recovery (`backend/app/recovery/service.py`), HMAC-verified backup restore (`backend/app/backups/service.py`), and durable SQLite background job recovery (`backend/app/datalab/worker.py`).
   - **Verifiable Outcomes:** Proof-carrying incident receipts (`backend/app/incidents/`), audit chain verification (`backend/app/audit/service.py`), and `alembic upgrade head` on empty databases.
3. **Tests:** `backend/tests/test_stage4_devices_sessions.py`, `test_stage5_nodes_and_rotation.py`, `test_stage6_recovery_and_backups.py`, `test_stage13_datalab_and_worker.py`, `frontend/src/test/app.test.tsx`.
4. **Evidence:** `reports/evidence/crash_matrix.md`, `reports/test_report/summary.md`.
5. **Reproduction:** `py -3.12 -m alembic -c backend/alembic.ini upgrade head`
6. **Limitations:** Multi-node consensus (`sim-node-1..7`) is an in-process SQLite simulation, not physical distributed hosts.

---

## 4. Threat Model & Honesty (10 Points)
1. **Evaluates:** Clear trust boundaries, asset identification, and transparent disclosure of unimplemented or simulated features.
2. **Implementation & Source Paths:** `threat-model.json`, `docs/threat_model.md`, `docs/limitations.md`, `docs/REAL_IMPLEMENTATION_AUDIT.md`, `frontend/src/pages/ScorecardPage.tsx`, `/api/v1/evidence/scorecard`.
3. **Evidence:** `docs/REAL_IMPLEMENTATION_AUDIT.md`, `docs/INDEPENDENT_SECURITY_VERIFICATION.md`.
4. **Limitations:** Explicitly discloses `SIMULATED` nodes, `NOT ESTABLISHED` forward secrecy, `NOT IMPLEMENTED` ML-DSA, non-HSM key store, and non-authenticating camera demo.

---

## 5. Performance & Overhead (10 Points)
1. **Evaluates:** Measurable latency, throughput, CPU/memory overhead, and offline CPU-first execution without AI/ML bloat.
2. **Implementation & Source Paths:** `scripts/benchmark.py` (`perf_counter_ns` timing + `psutil` telemetry), `backend/app/detector/service.py` (deterministic rule engine, 0 ML imports).
3. **Evidence:** `reports/benchmarks/latest.json`, `reports/benchmarks/raw_samples.csv`, `reports/benchmarks/summary.md`.
4. **Reproduction:** `py -3.12 scripts/benchmark.py`
5. **Limitations:** Benchmarks measure single-host local SQLite and simulated nodes.

---

## 6. Usability & Documentation (10 Points)
1. **Evaluates:** Clarity of repository structure, setup reproducibility, operator console usability, and submission brief/demo readiness.
2. **Implementation & Source Paths:** `README.md`, `frontend/src/`, `docs/demo_script.md`, `reports/submission/QSHIELD_Project_Brief.pdf`.
3. **Tests:** `cd frontend && npm run test && npm run build`.
4. **Evidence:** `reports/submission/QSHIELD_Project_Brief.pdf`, `reports/evidence/screenshots/`.
5. **Limitations:** Browser-selected file integrity hashing covers user-chosen files only, not OS-wide kernel/antivirus scanning.

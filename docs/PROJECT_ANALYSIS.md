# Q-SHIELD — Project Analysis (Stage 0)

**Project:** Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane  
**Track:** Yugaantar DevForge — Track 4 ("Key Identity Guard / Trust, but verify")  
**Primary USP:** Proof-Carrying Trust Changes  
**Stage:** Stage 0 — Source Review, Repository Inspection & Implementation Baseline

---

## 1. Source Document Inventory & Findings

### 1.1 Files Inspected in Workspace
Only three markdown documents exist in `C:\Users\adhar\OneDrive\Desktop\Yugaantar`:
1. **`QSHIELD_PRD.md`** (630 lines) — Product Requirements Document derived from `QSHIELD_Master_Build_Prompt.pdf` (26 pages) and `Yugaantar DevForge Tracks.pdf`. Defines product goals, success criteria, 4 synthetic roles, scope/non-scope, 12 Functional Requirements (`FR-01` to `FR-12`), 12 Non-Functional Requirements (`NFR-01` to `NFR-12`), 5 core workflows, 14 demo scenarios, prioritization (P0/P1/P2), acceptance gates (`G0`–`G10`), and risks.
2. **`QSHIELD_TRD.md`** (1,120 lines) — Technical Requirements Document. Defines stack targets, modular monolith + deterministic simulator architecture, repository layout, `track4_service.py` stdin/stdout process contract, 16 backend modules, 18 logical data entities, 9-step fail-closed authorization algorithm, cryptographic design (ML-KEM-768, AES-256-GCM, HKDF-SHA-256, HMAC-SHA-256, SHA-256, OS CSPRNG, optional ML-DSA), key rotation state machine, 3–7 node simulator, crash recovery matrix (7 injection points), audit hash chain, deterministic non-ML detector, secure messaging lab, 16-page frontend console, testing strategy, `perf_counter_ns` benchmark methodology, threat model, and 12-phase build plan.
3. **`QSHIELD_Antigravity_Stage_Prompts.md`** (807 lines) — Stage-by-stage execution guide (Stages 0–12), global non-negotiable rules, project continuity requirements, and exit gates.

### 1.2 Missing Source Documents & Official Toolkit Files
The following referenced organizer/source files are **NOT present** in the workspace:
- `Yugaantar DevForge Tracks.pdf` (original track problem statement PDF)
- `QSHIELD_Master_Build_Prompt.pdf` (original 26-page master build prompt PDF)
- Organizer's official Track 4 toolkit / starter repository:
  - `docs/adapter-v1.md` (authoritative JSON schema for `track4_service.py`)
  - Python/Node starter & demo applications
  - Official practice datasets and label schemas (for Stage 8 detector evaluation)
  - Official evidence sheet and two-page brief template
  - Official local validator source and command specification

**Impact:** Because `docs/adapter-v1.md`, the official validator, and practice datasets are missing, exact JSON field names/error formats for `track4_service.py` and exact detector dataset column schemas **cannot be verified** in Stage 0 and must not be fabricated.

---

## 2. Track 4 Requirements Summary

### 2.1 Functional Requirements (`FR-01` to `FR-12`)
- **FR-01 — Toolkit Adapter Compatibility:** Single root entry point `track4_service.py`; reads 1 UTF-8 JSON object from `stdin`, writes 1 JSON object to `stdout`, diagnostics to `stderr`; persists state across fresh processes in `TRACK4_STATE_DIR` (or OS temp dir); implements `setup`, `read`, `revoke`, `audit`, `protected_read` (ML-KEM-768 + HMAC-SHA-256 over `UTF8(challenge + exact_stored_body)`).
- **FR-02 — Zero-Trust Authorization:** 9-step ordered server-side check (request validity -> active identity -> valid bound session -> session not expired/revoked -> trusted owned device -> actor permission -> enabled resource -> active non-revoked key -> policy/incident check). Fail closed; zero content leakage on deny.
- **FR-03 — Identity, Device & Session Lifecycle:** Synthetic actors/roles (`Owner/User`, `Security Operator`, `Admin`, `Auditor`); device states (`PENDING`, `TRUSTED`, `SUSPENDED`, `REVOKED`); revoked devices never reactivated; peer-bound opaque sessions; lost-device workflow with replacement enrolment and unaffected peer preservation.
- **FR-04 — Key Generation & Rotation:** State machine `PREPARED -> ACTIVE -> ROTATING -> ACTIVE_NEW` (`RETIRED`/`REVOKED`, terminal `COMPROMISED`). 4-phase rotation (`PREPARE`, `DISTRIBUTE`, `COMMIT`, `RETIRE`); default zero-grace cutoff; no reactivation of revoked/compromised keys.
- **FR-05 — Revocation Propagation:** 3–7 simulated logical nodes; central tombstone durable before ack; idempotent monotonic propagation; unreachable nodes report `NOT CONVERGED`; measure per-node delay and p50/p95/p99/max convergence.
- **FR-06 — Crash Recovery & Backup Integrity:** Durable rotation journal; 7 crash injection points; pre-commit reverts to prior key (unless superseded by revocation), post-commit recovers new key; integrity-protected backup manifests rejecting tampered, wrong-key, incomplete, or stale backups.
- **FR-07 — Audit Integrity & Evidence:** Append-only JSON ledger (`SHA256(prev_hash || canonical_event_bytes)`); CR/LF/control-char normalization; actor/action from server context only; verifier detects tamper, deletion, reordering, actor mutation, and boundary injection; proof-carrying incident receipts.
- **FR-08 — Explainable Suspicious-Activity Detection:** Deterministic rules + time-aware directed identity/service graph (zero ML); detects unauthorized/self-escalation, admin grants, revoked actor attempts, service anomalies, and multi-hop lateral movement; bounded reorder window + clock uncertainty flags; actual TP/FP/TN/FN, precision, recall, F1, false alerts/1k, time-to-alert on labelled data (or `NOT EVALUATED`).
- **FR-09 — Secure Messaging & Session Security:** AEAD encryption with authenticated AAD; recipient binding before decrypt; durable replay ledger; loss/reordering recovery; peer-bound expiry-bound session resumption; honest forward-secrecy status (`NOT ESTABLISHED` unless proven).
- **FR-10 — Dashboard & Operational UX:** 16-page React/TypeScript operator console backed by real endpoints; 14 resettable scenarios; honest `SIMULATED` and `NOT CONVERGED` labels.
- **FR-11 — Benchmarking:** `time.perf_counter_ns` with warmups/repeated samples across adapter, crypto, policy, audit, backup, rotation, convergence, detector, API, and messaging; outputs JSON, CSV, and Markdown.
- **FR-12 — Evidence & Submission:** Traceability, acceptance gates, threat model, crypto design, limitations, README, pinned dependencies, test/coverage reports, validator output, two-page brief PDF, and 5-minute demo script/recording.

### 2.2 Non-Functional Requirements & Hard Constraints
- **Offline-first & CPU-first (`NFR-01`, `NFR-03`):** No cloud dependencies, external APIs, or GPU requirements in judge mode.
- **No AI/ML (`NFR-03`):** Strictly prohibited in submitted runtime.
- **No Custom Crypto:** Vetted library APIs only (`pqcrypto`, `cryptography`, `hashlib`/`hmac`, OS CSPRNG).
- **No Hardcoded Secrets (`NFR-06`):** No keys, tokens, or protected plaintext in logs, errors, UI evidence, or repo.
- **Honest Claims (`NFR-10`):** Simulated nodes are not physical distributed servers; SQLite is not distributed consensus; forward secrecy is `NOT ESTABLISHED` unless proven.
- **Synthetic Data Only:** No real PII or external/unauthorized testing.

---

## 3. Repository & Environment Inspection

### 3.1 Existing Repository State
- **Git Status:** Not a git repository (`.git` absent).
- **Code/Config/Tests:** None exist yet. This is a greenfield workspace containing only the 3 planning markdown files (`QSHIELD_PRD.md`, `QSHIELD_TRD.md`, `QSHIELD_Antigravity_Stage_Prompts.md`).
- **Reusable Components:** Only the specifications in the 3 markdown files; no existing source code or tests to reuse.

### 3.2 Local Runtime & Dependency Audit
Verified via command execution on 2026-11-26:
- **Python:** `3.11.9` (TRD specifies `3.12` for official worker; compatibility must be verified).
- **Node.js / npm:** `v22.19.0` / `10.9.3` (TRD mentions `24.11.1` for official worker).
- **Git:** `2.51.0.windows.1`.
- **Installed Python Packages (relevant):** `fastapi==0.136.1`, `pydantic==2.13.3`, `cryptography==48.0.0`, `uvicorn==0.46.0`, `httpx==0.28.1`, `psutil==7.2.2`.
- **Missing Python Packages:**
  - `pqcrypto` (TRD specifies `0.4.0` — **critical blocker** for Stage 1 `protected_read` and Stage 3 ML-KEM-768).
  - `SQLAlchemy` (v2.x) and `alembic` (required for Stage 2).
  - `pytest` and `pytest-cov` (required for testing/coverage).
- **Frontend Packages:** `frontend/` does not exist yet; React, Vite, Tailwind, TanStack Query, React Router, Recharts will be installed in Stage 10.

---

## 4. Technical Constraints & Risks

1. **Missing Official Toolkit (`docs/adapter-v1.md` & Validator):** Highest risk. Implementing `track4_service.py` without the exact organizer JSON schema risks contract mismatch. Mitigation: Acquire official toolkit before Stage 1, or implement strictly from master prompt specs and mark validator `BLOCKED` until available.
2. **`pqcrypto` Installation & Python Version:** `pqcrypto` is not currently installed, and local Python is `3.11.9` vs `3.12` in TRD. Mitigation: Verify `pqcrypto` wheel availability and exact ML-KEM-768 APIs before Stage 1 coding.
3. **Scope vs. Hackathon Timeline:** 12 stages covering PQC, zero-trust RBAC, 3–7 node simulation, crash recovery, audit chaining, non-ML graph detection, secure messaging, 16-page UI, and benchmarks. Mitigation: Strictly follow P0-first build order; keep modular monolith architecture; defer optional ML-DSA and OAuth (P2).
4. **Honesty in Security Claims:** Forward secrecy, HSM-grade key protection, and distributed consensus cannot be claimed without proof/infrastructure. Mitigation: Explicit `docs/limitations.md` and UI/scorecard labels (`SIMULATED`, `NOT CONVERGED`, `NOT ESTABLISHED`).

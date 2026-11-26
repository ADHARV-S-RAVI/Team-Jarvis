# Q-SHIELD — System Architecture

**Project:** Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane  
**Track:** Yugaantar DevForge — Track 4 ("Key Identity Guard / Trust, but verify")  
**Status:** Stage 0 Architecture Baseline (Offline-First, CPU-First Modular Monolith)

---

## 1. Architectural Principles

1. **Modular Monolith + Deterministic Simulator:** Single-process FastAPI backend with well-defined domain modules and a deterministic 3–7 node local simulator. No microservices, cloud queues, or distributed consensus claims.
2. **Toolkit Adapter Isolation:** Exactly one root entry point (`track4_service.py`) that reads one UTF-8 JSON object from `stdin`, writes one JSON object to `stdout`, logs diagnostics only to `stderr`, and persists state in `TRACK4_STATE_DIR` (or OS temp directory). It has zero dependency on the frontend, FastAPI server, or external network.
3. **Fail-Closed Zero-Trust Authorization:** Every protected operation executes an ordered 9-step server-side decision pipeline. Any unknown, missing, expired, revoked, or inconsistent state denies access without leaking protected content or key material.
4. **No Custom Cryptography & No AI/ML:** All cryptographic operations use vetted libraries (`pqcrypto` for ML-KEM-768, `cryptography` for AES-256-GCM and HKDF-SHA-256, Python `hashlib`/`hmac` for SHA-256/HMAC-SHA-256, and OS CSPRNG). Threat detection uses purely deterministic rules, statistics, and time-aware graph logic.
5. **Proof-Carrying Trust Changes:** Every revoke, rotate, or re-enrol operation produces an incident receipt linking actor, policy decision, state transition, node acknowledgements, convergence timing, verification results, and audit-chain reference.

---

## 2. High-Level System Topology

```text
+-----------------------------------------------------------------------+
|                        React + TypeScript UI                          |
|         Operator Console / Scenario Runner / Scorecard (Vite)         |
+-----------------------------------+-----------------------------------+
                                    | Local HTTP/JSON (/api/v1/*)
+-----------------------------------v-----------------------------------+
|                     FastAPI + Pydantic v2 API Layer                   |
|          Request Validation, Correlation ID, Auth/RBAC, Errors        |
+-----------------------------------+-----------------------------------+
                                    |
+-----------------------------------v-----------------------------------+
|                      Policy Decision Point (PDP)                      |
|      9-Step Ordered Zero-Trust Evaluation (Fail-Closed, Reason Codes) |
+---+-------------------------------+-------------------------------+---+
    |                               |                               |
+---v-------------------+   +-------v---------------+   +-----------v---+
| Domain Services       |   | Crypto Provider       |   | Audit &       |
| - identity            |   | - ML-KEM-768 (pqcrypto|   | Evidence      |
| - devices             |   | - AES-256-GCM (AEAD)  |   | - Hash Chain  |
| - vault               |   | - HKDF-SHA-256        |   | - Receipts    |
| - keys                |   | - HMAC-SHA-256        |   | - Scorecard   |
| - incidents           |   | - OS CSPRNG           |   +-------+-------+
+---+-------------------+   +-------+---------------+           |
    |                               |                           |
+---v-------------------------------v---------------------------v-------+
|                  SQLite + WAL + Rotation Journal                      |
|     Actors, Devices, Sessions, Keys, Tombstones, Audit, Incidents     |
+---+-------------------------------+-------------------------------+---+
    |                               |                               |
+---v---------------+   +-----------v-----------+   +---------------v---+
| Node Simulator    |   | Recovery & Backups    |   | Deterministic     |
| 3-7 Logical Nodes |   | Rotation Journal      |   | Detector & Graph  |
| Partition/Latency |   | Crash Injection       |   | Clock Skew/Metrics|
| Convergence Timer |   | Signed/AEAD Manifests |   | (No ML/AI)        |
+-------------------+   +-----------------------+   +-------------------+

Separate Organizer Toolkit Path (Process-per-Request, No Frontend/Server):
Organizer Worker -> track4_service.py -> Adapter Domain/Storage -> TRACK4_STATE_DIR
```

---

## 3. Core Subsystems & Module Responsibilities

### 3.1 Toolkit Adapter (`track4_service.py`)
- **Interface:** Stdin/stdout JSON-over-process (new process per request).
- **State Persistence:** Durable JSON/SQLite state in `TRACK4_STATE_DIR` (fallback to OS temp dir per official spec).
- **Operations:** `setup`, `read`, `revoke`, `audit`, `protected_read`.
- **Security:** Redacts `key_material`, shared secrets, and protected bodies from `stderr` and error responses. Uses `pqcrypto` ML-KEM-768 + `HMAC-SHA-256(shared_secret, UTF8(challenge + stored_body))`.

### 3.2 Frontend (`frontend/`)
- **Stack:** React, TypeScript, Vite, Tailwind CSS, accessible shadcn-style components, TanStack Query, React Router, Recharts.
- **Role:** Thin operator console; all security decisions and state mutations occur on the backend.
- **Key Views:** Landing, Demo Login, Overview, Identity & Access, Devices & Lost-Device Workflow, Secure Vault, Key Lifecycle, Node Control Plane, Incident Center, Detection & Lateral Movement, Secure Messaging Lab, Audit & Evidence, Benchmark Lab, Attack/Failure Simulation, Requirements Scorecard, Settings/Docs.
- **Honesty Rules:** Simulated nodes explicitly labelled `SIMULATED`; unreachable nodes show `NOT CONVERGED`; forward secrecy shows `NOT ESTABLISHED` unless proven; charts use real measured data or explicitly labelled seeded demo data.

### 3.3 Backend (`backend/app/`)
- **Stack:** Python (target 3.12; local 3.11.9 verified in Stage 0), FastAPI, Pydantic v2, SQLAlchemy 2, Alembic.
- **API Prefix:** `/api/v1/` with typed schemas, correlation IDs, and fail-closed error handling.
- **Authorization Pipeline (9-step ordered check):**
  1. Valid request schema
  2. Identity exists and is enabled
  3. Authenticated session exists and is bound to actor
  4. Session is not expired or revoked
  5. Device belongs to actor, is enrolled/trusted, and is not revoked
  6. Actor has required role/permission
  7. Resource exists and is enabled
  8. Key version is active and not revoked/compromised
  9. Incident/policy does not deny

### 3.4 Database & Persistence (`backend/app/db/`)
- **Engine:** SQLite with foreign keys enabled (`PRAGMA foreign_keys = ON`), WAL mode where appropriate, busy timeout, and ACID transactions.
- **Migrations:** Alembic migrations runnable from an empty database, plus deterministic demo seed/reset.
- **Key Entities:** `Actor`, `Device`, `Session`, `Resource`, `KeyMetadata`, `RotationJournal`, `RevocationTombstone`, `SimulatedNode`, `NodeAcknowledgement`, `AuditEvent`, `Incident`, `IncidentReceipt`, `DetectorEvent`, `DetectorAlert`, `Message`, `ReplayRecord`, `BenchmarkRun`, `ScenarioRun`.
- **Durability Caveat:** SQLite provides local ACID durability on a single host, not distributed consensus.

### 3.5 Cryptographic Provider (`backend/app/crypto/`)
- **ML-KEM-768:** Vetted `pqcrypto` API for `protected_read` and PQC shared-secret establishment (exact API/sizes to be verified against installed package).
- **AES-256-GCM:** Authenticated encryption for vault resources (random DEK per resource) and secure messaging. Unique nonces via OS CSPRNG; AAD binds schema version, sender/recipient, resource/message ID, key version, algorithm, timestamp/expiry, and session ID.
- **HKDF-SHA-256:** Purpose-separated key derivation (KEM, identity, resource DEK, session, audit signing).
- **HMAC-SHA-256 & SHA-256:** Toolkit `protected_read` proof, audit hash chaining, and backup manifest integrity.
- **ML-DSA (Optional):** Deferred unless vetted library support and test vectors are verified.

### 3.6 Device Identity & Lifecycle (`backend/app/identity/`, `backend/app/devices/`, `backend/app/auth/`)
- **Identities:** Synthetic actors with least-privilege roles (`Owner/User`, `Security Operator`, `Admin`, `Auditor`). Self-escalation blocked.
- **Devices:** States (`PENDING`, `TRUSTED`, `SUSPENDED`, `REVOKED`). Stores credential fingerprint, never raw reusable credentials. Revoked devices can never be reactivated; replacement enrolment does not restore trust to the old device.
- **Sessions:** Opaque tokens (hashed at rest), bound to actor, device, and authenticated peer. Immediate invalidation on logout/revocation.

### 3.7 Revocation, Key Rotation & Crash Recovery (`backend/app/keys/`, `backend/app/recovery/`, `backend/app/backups/`)
- **Key State Machine:** `PREPARED -> ACTIVE -> ROTATING -> ACTIVE_NEW`; previous key transitions to `RETIRED` or `REVOKED`. `COMPROMISED` is terminal. `REVOKED` and `COMPROMISED` keys never reactivate.
- **4-Phase Rotation:** `PREPARE` -> `DISTRIBUTE` -> `COMMIT` (atomic pointer/epoch update) -> `RETIRE` (zero-grace cutoff by default).
- **Rotation Journal:** Records `operation_id`, `previous_version`, `proposed_version`, `phase`, `committed` flag, `integrity_hash`, `actor_id`, and timestamps.
- **Crash Recovery:** Pre-commit crashes revert to prior authorized version (unless superseded by revocation); post-commit crashes recover new committed version. Tombstones survive restarts and stale restores.
- **Backups:** Integrity-protected manifests; verified before restore; rejects tampering, wrong key, incomplete, or stale backups.

### 3.8 Multi-Node Simulator (`backend/app/nodes/`)
- **Scope:** 3–7 configurable logical nodes (local deterministic simulation).
- **State per Node:** `node_id`, `service_name`, `accepted_key_version`, `revoked_state`, `last_sequence`, `health`, `delay_ms`, `ack_at`, `enforced_at`, `fault_state`.
- **Propagation:** Idempotent and monotonic; stale updates cannot undo revocations. Unreachable/partitioned nodes report `NOT CONVERGED`.
- **Metrics:** Per-node enforcement delay, total convergence (`last_node_enforced_at - revoke_started_at`), p50/p95/p99/max across runs, and post-cutoff old-key acceptance count (target 0).

### 3.9 Audit Logging & Proof-Carrying Receipts (`backend/app/audit/`, `backend/app/incidents/`, `backend/app/evidence/`)
- **Append-Only Ledger:** Structured JSON records with `event_id`, monotonic `sequence`, UTC timestamp, server-authenticated `actor_id`, `action`, `target`, `decision`, `reason`, `correlation_id`, `key_version`, sanitized metadata, `prev_hash`, and `event_hash = SHA256(prev_hash || canonical_event_bytes)`.
- **Injection Defense:** Control characters (CR/LF) normalized/escaped, text lengths capped, actor/action strictly from authenticated context and enums. Secrets/plaintext redacted.
- **Verifier:** Detects modification, deletion, reordering, actor mutation, and boundary injection.
- **Receipts:** Links `Incident` -> `policy_decision` -> `state_transition` -> `node_acks` -> `convergence_ms` -> `audit_ref`.

### 3.10 Deterministic Threat Detection (`backend/app/detector/`)
- **Zero-ML Engine:** Deterministic rules, statistical baselines, and time-aware directed identity/service graph.
- **Rules:** Unauthorized/self privilege escalation, unexpected admin grant, revoked actor attempts, unusual service access/counts, sensitive service access after privilege change, and multi-hop lateral movement paths (even with valid credentials).
- **Clock Handling:** Stores `event_time`, `observed_at`, and `clock_offset`; configurable bounded reorder window and watermarks; marks overlapping intervals as order-uncertain.
- **Metrics:** Actual TP/FP/TN/FN, precision, recall, F1, false alerts per 1,000 benign events, median/p95 time-to-alert on labelled data (or `NOT EVALUATED` if labels absent).

### 3.11 Secure Messaging Lab (`backend/app/messaging/`)
- **Encryption:** Vetted AEAD (AES-256-GCM) with AAD binding protocol version, message ID, sender, recipient, session ID, key version, timestamp/expiry.
- **Controls:** Recipient verification before decryption; durable `ReplayRecord` rejecting duplicate IDs/sequences; bounded reorder/loss buffer; peer-bound, expiry-bound session resumption tokens.
- **Forward Secrecy:** Explicitly marked `NOT ESTABLISHED` unless a vetted ephemeral/ratcheting protocol is implemented and proven by tests.

### 3.12 Testing, Validation & Benchmarking (`tests/`, `backend/app/benchmarks/`, `scripts/`)
- **Testing:** Independent black-box tests for adapter processes, crypto KAT/interop, authorization invariants, crash matrix, audit tamper, detector metrics, messaging, and UI smoke tests.
- **Benchmarking:** `time.perf_counter_ns` with warmups and repeated samples; outputs raw CSV, `reports/benchmarks/latest.json`, and Markdown summaries.

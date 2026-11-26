# Q-SHIELD --- Technical Requirements Document (TRD)

**Track:** Yugaantar DevForge --- Track 4\
**Product:** Q-SHIELD --- Quantum-Ready Trust & Revocation Control
Plane\
**Version:** 1.0\
**Status:** Proposed technical baseline; confirm exact organizer
toolkit/runtime before implementation.

------------------------------------------------------------------------

## 1. Technical objectives

Build a reproducible, CPU-first, offline modular monolith with: - One
exact toolkit adapter entry point. - A typed FastAPI backend and
persistent SQLite state. - A React/TypeScript operator console. - Vetted
cryptographic library APIs only. - Deterministic multi-node
simulation. - Independent adapter, security, crypto, recovery, detector,
messaging and E2E tests. - Actual benchmark and evidence output.

No AI/ML inference, LLM, embeddings, model API, custom cryptographic
primitive, cloud dependency or external network is permitted in judge
mode.

## 2. Runtime and technology stack

  ------------------------------------------------------------------------
  Layer                   Proposed technology      Constraints / notes
  ----------------------- ------------------------ -----------------------
  Toolkit adapter         Python 3.12,             Exactly one root
                          `track4_service.py`      adapter; one JSON
                                                   input/output per
                                                   process.

  Backend                 FastAPI, Pydantic v2,    Typed contracts, domain
                          SQLAlchemy 2, Alembic    services, backend
                                                   authorization.

  Database                SQLite, WAL where        Foreign keys, busy
                          appropriate              timeout, transactions;
                                                   portable schema where
                                                   practical.

  PQC                     `pqcrypto==0.4.0` in     Verify ML-KEM-768 API
                          official worker          and exact
                                                   key/ciphertext sizes
                                                   against installed
                                                   package.

  Symmetric crypto        `cryptography` AES-GCM / Vetted APIs only;
                          HKDF where supported     unique nonce per key.

  Hash/HMAC               Python standard library  SHA-256 audit/manifest;
                                                   HMAC-SHA-256 exact
                                                   protected-read proof.

  Frontend                React + TypeScript +     Desktop-first
                          Vite                     responsive console.

  UI                      Tailwind + accessible    Consistent states,
                          shadcn-style components  keyboard accessibility,
                                                   reduced motion.

  Data fetching/routing   TanStack Query, React    Typed API client and
                          Router                   cache invalidation.

  Charts                  Recharts or equivalent   Real backend data or
                                                   explicitly labelled
                                                   seeded data.

  Tests                   pytest, pytest-cov,      Independent black-box
                          HTTPX/TestClient;        contract/security
                          Playwright if time       tests.

  Benchmark               Python                   Warmups, repeated
                          `time.perf_counter_ns`   samples, raw CSV/JSON
                                                   and summary.
  ------------------------------------------------------------------------

Pin exact versions only after checking the organizer worker image and
available packages. The prompt identifies Python 3.12, `pqcrypto==0.4.0`
and Node 24.11.1 for the official worker; confirm against the current
toolkit before relying on them.

## 3. High-level architecture

``` text
                           ┌─────────────────────────┐
                           │ React + TypeScript UI   │
                           │ Operator / Demo Console │
                           └────────────┬────────────┘
                                        │ HTTPS/local API
                           ┌────────────▼────────────┐
                           │ FastAPI + Pydantic      │
                           │ Authentication / RBAC  │
                           │ Policy Decision Point   │
                           └────────────┬────────────┘
                                        │
             ┌──────────────────────────┼──────────────────────────┐
             │                          │                          │
   ┌─────────▼─────────┐      ┌─────────▼─────────┐      ┌─────────▼─────────┐
   │ Domain Services   │      │ Crypto Provider   │      │ Audit / Evidence │
   │ Identity / Device │      │ ML-KEM / AES-GCM  │      │ Hash Chain       │
   │ Keys / Vault      │      │ HKDF / HMAC       │      │ Receipt Verifier │
   │ Sessions / Policy │      └─────────┬─────────┘      └─────────┬─────────┘
   └─────────┬─────────┘                │                          │
             └──────────────────────────┼──────────────────────────┘
                                        │
                           ┌────────────▼────────────┐
                           │ SQLite + Journal       │
                           │ Key Metadata / State   │
                           │ Revocation Tombstones  │
                           └────────────┬────────────┘
                                        │
                 ┌──────────────────────┼───────────────────────┐
                 │                      │                       │
       ┌─────────▼─────────┐  ┌─────────▼─────────┐   ┌─────────▼─────────┐
       │ Node Simulator    │  │ Recovery / Backup │   │ Detector / Graph  │
       │ 3–7 logical nodes │  │ Rotation Journal  │   │ Rules / Metrics   │
       └───────────────────┘  └───────────────────┘   └───────────────────┘

Separate adapter path:
Organizer worker → track4_service.py → domain/adapter services → persistent state
```

**Architecture rule:** use a modular monolith plus deterministic
simulated nodes. Do not introduce microservices, cloud queues or real
distributed infrastructure during the hackathon. Keep the toolkit
adapter independent of the frontend and external services.

## 4. Repository layout

``` text
q-shield/
├── track4_service.py                 # ONLY toolkit root entry point
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── api/v1/
│   │   ├── auth/
│   │   ├── identity/
│   │   ├── devices/
│   │   ├── policy/
│   │   ├── vault/
│   │   ├── crypto/
│   │   ├── keys/
│   │   ├── nodes/
│   │   ├── recovery/
│   │   ├── backups/
│   │   ├── audit/
│   │   ├── detector/
│   │   ├── messaging/
│   │   ├── benchmarks/
│   │   ├── evidence/
│   │   ├── db/
│   │   ├── schemas/
│   │   └── services/
│   └── tests/
├── frontend/
│   └── src/
│       ├── app/
│       ├── pages/
│       ├── components/
│       ├── features/
│       ├── hooks/
│       ├── services/
│       └── styles/
├── datasets/
│   ├── fixtures/
│   ├── generated/
│   └── README.md
├── scripts/
│   ├── run_dev.sh
│   ├── clean_reset.sh
│   ├── benchmark.py
│   ├── generate_synthetic_events.py
│   ├── test_toolkit_adapter.sh
│   └── security_checks.sh
├── docs/
│   ├── source_requirements.md
│   ├── requirement_traceability.csv
│   ├── assumptions_and_open_questions.md
│   ├── crypto_design.md
│   ├── threat_model.md
│   ├── architecture.md
│   ├── api.md
│   ├── benchmark_methodology.md
│   ├── acceptance_gates.md
│   ├── limitations.md
│   └── demo_script.md
├── reports/
│   ├── test_report/
│   ├── benchmarks/
│   ├── detector/
│   └── evidence/
├── tests/
│   ├── adapter/
│   ├── crypto/
│   ├── security/
│   ├── recovery/
│   ├── detector/
│   ├── messaging/
│   ├── integration/
│   └── e2e/
├── README.md
├── pyproject.toml
├── requirements.lock
├── .env.example
└── .gitignore
```

Do not commit secrets, private keys, real PII, `.env`, large generated
datasets, build artifacts or an unlicensed wholesale copy of the
organizer toolkit. Use Git LFS only if needed and within organizer
repository limits.

## 5. Toolkit adapter contract

### 5.1 Process contract

-   Entry point: `track4_service.py` only.
-   One UTF-8 JSON object is read from stdin to EOF.
-   Exactly one valid JSON object is written to stdout.
-   Diagnostics only to stderr.
-   Process exits cleanly; no child processes left running.
-   State is persisted before acknowledging a mutation.
-   The adapter must work when invoked in a new process for every
    request.
-   Use `TRACK4_STATE_DIR` when provided; otherwise use the OS temporary
    directory as specified by the organizer.
-   IDs are opaque strings.
-   Never log keys, shared secrets, synthetic key material or protected
    bodies.

### 5.2 Operations

  ---------------------------------------------------------------------------------
  Operation               Input (conceptual)      Required behavior
  ----------------------- ----------------------- ---------------------------------
  `setup`                 owners map, contents    Initialize/reset state durably;
                          map, disabled actor     return `{"ready": true}` only
                          IDs, synthetic key      after complete initialization.
                          material                

  `read`                  actor, asset,           Owner receives exact stored body;
                          request_id              unauthorized caller receives
                                                  `{"decision":"deny"}` with no
                                                  body or metadata leakage.

  `revoke`                actor                   Persist actor revocation before
                                                  success; other actors remain
                                                  authorized.

  `audit`                 request_id              Return exact recorded request ID
                                                  and decision; actor/action/event
                                                  boundary cannot be forged through
                                                  input text.

  `protected_read`        actor, asset,           Authorize first; decode standard
                          challenge, public_key   Base64 raw ML-KEM-768 public key;
                                                  encapsulate with vetted API;
                                                  return ciphertext Base64 and
                                                  lowercase-hex HMAC-SHA-256 over
                                                  UTF-8
                                                  `challenge + exact_stored_body`
                                                  with no separator.
  ---------------------------------------------------------------------------------

The detailed JSON schema and exact response behavior must be taken from
the current official `docs/adapter-v1.md` and validator, not inferred
from this summary.

### 5.3 Adapter acceptance tests

-   Fresh setup and setup reset.
-   Owner and peer-owner exact content read.
-   Wrong owner denied with empty/no protected body.
-   Revoke persists across a fresh process.
-   Revoked owner denied; unaffected peer remains allowed.
-   Audit request ID and decision correlation.
-   `protected_read` independently decapsulates and recomputes HMAC.
-   Malformed Base64/key/challenge fails safely.
-   Synthetic key marker absent from stdout and stderr.
-   Exactly one JSON object on stdout.
-   No process leftovers and clean exit.
-   Official validator passes without modifying official toolkit files.

## 6. Backend modules and responsibilities

  -----------------------------------------------------------------------
  Module                              Responsibility
  ----------------------------------- -----------------------------------
  `auth`                              Synthetic demo authentication,
                                      session issuance and logout.

  `identity`                          Actors, roles, enabled/disabled
                                      status and permissions.

  `devices`                           Device enrolment, ownership, trust
                                      state and revocation.

  `policy`                            Ordered zero-trust decision
                                      evaluation and reason codes.

  `vault`                             Protected resources, ownership and
                                      authorized read.

  `crypto`                            Vetted crypto provider facade; no
                                      custom primitives.

  `keys`                              Key metadata, versions, rotation
                                      and revocation state machines.

  `nodes`                             Logical node state, propagation,
                                      acknowledgements and faults.

  `recovery`                          Journal, idempotent reconciliation
                                      and crash recovery.

  `backups`                           Manifest creation, verification and
                                      safe restore.

  `audit`                             Canonical event serialization, hash
                                      chain, verification and export.

  `detector`                          Rule engine, event parser, graph
                                      paths, clock handling and metrics.

  `messaging`                         E2E demo messages, replay ledger,
                                      delivery and session resumption.

  `benchmarks`                        Repeatable measurements and report
                                      persistence.

  `incidents`                         Incident lifecycle, response
                                      workflow and proof-carrying
                                      receipts.

  `evidence`                          Requirement scorecard and links
                                      from scenario to test/audit
                                      artifacts.
  -----------------------------------------------------------------------

## 7. Data model

Use SQLAlchemy models and Alembic migrations. The following is the
logical minimum; exact columns and indexes are refined during
implementation.

  -----------------------------------------------------------------------
  Entity                              Important fields
  ----------------------------------- -----------------------------------
  Actor                               `id`, `display_label`, `role`,
                                      `enabled`, `created_at`

  Device                              `id`, `owner_actor_id`,
                                      `credential_fingerprint`, `state`,
                                      `state_version`, `enrolled_at`,
                                      `last_seen_at`, `revocation_reason`

  Session                             `id`, `token_hash`, `actor_id`,
                                      `device_id`, `peer_id`,
                                      `issued_at`, `expires_at`,
                                      `revoked_at`, `version`

  Resource                            `id`, `owner_actor_id`,
                                      `content_ref/ciphertext`,
                                      `key_version`, `state`,
                                      `created_at`

  KeyMetadata                         `id`, `version`, `algorithm`,
                                      `state`, `created_at`,
                                      `activated_at`, `retired_at`,
                                      `compromised_at`

  RotationJournal                     `operation_id`, `previous_version`,
                                      `proposed_version`, `phase`,
                                      `committed`, `integrity_hash`,
                                      `actor_id`, timestamps

  RevocationTombstone                 `subject_type`, `subject_id`,
                                      `epoch/sequence`, `reason`,
                                      `created_at`

  SimulatedNode                       `id`, `service_name`,
                                      `accepted_key_version`,
                                      `last_sequence`, `health`,
                                      `last_ack_at`, `fault_state`

  NodeAcknowledgement                 `operation_id`, `node_id`,
                                      `sequence`, `ack_at`,
                                      `enforced_at`, `result`

  AuditEvent                          `event_id`, `sequence`,
                                      `timestamp`, `actor_id`, `action`,
                                      `target`, `decision`, `reason`,
                                      `correlation_id`, `metadata`,
                                      `prev_hash`, `event_hash`

  Incident                            `id`, `type`, `severity`, `status`,
                                      `initiator`, `reason`,
                                      `created_at`, `closed_at`

  IncidentReceipt                     `id`, `incident_id`,
                                      `policy_decision`,
                                      `state_transition`, `node_acks`,
                                      `convergence_ms`, `verification`,
                                      `audit_ref`

  DetectorEvent                       `id`, `source`, `observed_at`,
                                      `event_time`, `clock_offset`,
                                      `actor`, `service`, `action`,
                                      `schema_version`, `payload`

  DetectorAlert                       `id`, `rule_id`, `severity`,
                                      `score_breakdown`, `path`,
                                      `event_refs`, `created_at`,
                                      `explanation`

  Message                             `id`, `sender_id`, `recipient_id`,
                                      `session_id`, `key_version`,
                                      `nonce`, `ciphertext`, `aad`,
                                      `status`, timestamps

  ReplayRecord                        `message_id`, `recipient_id`,
                                      `sequence`, `accepted_at`, `result`

  BenchmarkRun                        `id`, `environment`, `seed`,
                                      `started_at`, `completed_at`,
                                      `raw_report_ref`, `summary`

  ScenarioRun                         `id`, `scenario_type`, `seed`,
                                      `status`, `assertions`,
                                      `failed_checks`, `audit_refs`,
                                      `timings`
  -----------------------------------------------------------------------

Use unique constraints for opaque IDs, message IDs and replay sequences
where appropriate. Add indexes for event sequence/time, actor,
correlation ID, node and incident lookups. Enforce foreign keys and
transactions.

## 8. Authorization decision algorithm

For every protected request, execute the following server-side checks in
order:

1.  Parse and validate request.
2.  Identity exists and is enabled.
3.  Authenticated session is valid and bound to the identity.
4.  Session is not expired or revoked.
5.  Device belongs to actor, is enrolled/trusted and not revoked.
6.  Actor has permission for the resource/action.
7.  Resource exists and is not disabled.
8.  Key version is active and not revoked/compromised.
9.  Incident or policy does not deny.
10. Return `ALLOW` or `DENY` with structured reason code and correlation
    ID.

Unknown state, storage inconsistency or policy error must fail closed.
No protected body, snippet, key or content-bearing metadata may appear
in a denial or error response.

## 9. Cryptographic design

### 9.1 Required algorithms

  -------------------------------------------------------------------------------------------------------
  Algorithm               Purpose                 Implementation rule
  ----------------------- ----------------------- -------------------------------------------------------
  ML-KEM-768              Toolkit                 Use vetted `pqcrypto` API; verify parameter names and
                          `protected_read` and    byte sizes from installed implementation/tests.
                          PQC shared-secret       
                          establishment           

  AES-256-GCM             Resource/message        Vetted AEAD API; unique nonce per key; authenticate
                          encryption              metadata as AAD.

  HKDF-SHA-256            Purpose-separated       Vetted API or standard implementation; context labels
                          session/key derivation  and IDs in `info`.

  HMAC-SHA-256            Exact toolkit proof     `HMAC(shared_secret, UTF8(challenge + stored_body))`,
                                                  no separator; lowercase hex.

  SHA-256                 Audit chain and backup  Hash alone is not authentication; document
                          manifest hashing        anchoring/signing trust.

  OS CSPRNG               Nonces and random       Use operating-system cryptographic randomness through
                          material                vetted APIs.

  ML-DSA (optional)       Signed administrative   Only after supported parameter level/API and test
                          commands/checkpoints    vectors are verified.
  -------------------------------------------------------------------------------------------------------

### 9.2 AES-GCM associated data

Bind at minimum: - Schema/protocol version. - Sender and recipient IDs
where applicable. - Resource/message ID. - Key version and algorithm. -
Nonce. - Timestamp and expiry. - Session ID.

Do not release plaintext until authentication succeeds. AAD or
ciphertext tampering must fail closed.

### 9.3 Key handling

-   Store key IDs/versions in application metadata; never expose secret
    material in API/UI/logs.
-   Separate identity signing, KEM, file DEK, session and audit-signing
    purposes.
-   Use random DEKs per resource where envelope encryption is
    implemented.
-   Protect DEKs with a vetted wrapping/derivation mechanism.
-   Restrict local key-store file permissions; document that this is not
    an HSM.
-   Startup crypto self-tests and independent test
    vectors/interoperability tests are required.
-   No hand-rolled KEM, signature, AEAD or ratchet.

### 9.4 Forward secrecy

Use a vetted protocol/library supporting ephemeral exchange and session
evolution only if available and feasible. Otherwise label forward
secrecy "not established"; do not imply that ML-KEM alone provides it.

## 10. Key lifecycle and rotation

### 10.1 State model

``` text
PREPARED → ACTIVE → ROTATING → ACTIVE_NEW
                            └→ old key RETIRED or REVOKED

COMPROMISED = terminal state
REVOKED     = cannot be reactivated
```

### 10.2 Rotation phases

1.  `PREPARE`: generate/verify new key metadata and backup.
2.  `DISTRIBUTE`: stage new version on nodes and collect
    acknowledgements.
3.  `COMMIT`: atomically update active-version pointer/epoch.
4.  `RETIRE`: deny old key after cutoff and update node state.

Every phase is idempotent. Persist operation ID, previous/proposed
versions, phase, commit flag, integrity hashes, actor and timestamps.

### 10.3 Cutoff and in-flight behavior

Default is zero grace for new requests after commit/cutoff. If an
optional grace mode is built, it must be disabled by default and have
precise tested semantics. Any transfer allowed to complete must be
explicitly marked as in-flight and governed by policy. No new request
may use an old key after cutoff.

## 11. Revocation and simulated node convergence

-   Minimum three logical nodes; configurable 3--7.
-   Each node stores node ID/service, accepted key version, revoked
    key/actor/device versions, last sequence/event, health, propagation
    delay, acknowledgement/enforcement timestamps and fault state.
-   Central tombstone and sequence are persisted before acknowledging
    revocation.
-   Central policy immediately denies new requests after commit.
-   Nodes accept only authenticated/verified monotonic updates; stale or
    duplicate updates are ignored idempotently.
-   Per-node delay: `node_enforced_at - revoke_started_at`.
-   Overall convergence: `last_node_enforced_at - revoke_started_at`.
-   If any node is unreachable, state remains "not converged"; apply
    documented fail-closed behavior for that node.
-   Simulate latency, partition, recovery and reconciliation only
    against local synthetic nodes.

Required metrics: - Nodes converged / total. - Per-node enforcement
delay. - Convergence p50/p95/p99/max across runs. - Old-key post-cutoff
acceptance count (target 0). - Unaffected authorized peer success. -
Replacement-device re-enrolment success and old-device denial.

## 12. Crash recovery and backups

### 12.1 Recovery semantics

-   Crash before commit: recover previous active key unless a newer
    revocation supersedes it.
-   Crash after commit: recover new committed key.
-   Revocation tombstones survive every restart and stale snapshot.
-   Inconsistent state fails closed and reports recovery guidance.
-   Journal phases and node reconciliation are idempotent.

### 12.2 Crash injection points

-   After prepare.
-   After backup.
-   After node 1/2 acknowledgement.
-   Before commit.
-   Immediately after commit.
-   During retirement.
-   After revocation tombstone.

### 12.3 Backup verification

Backup includes integrity-protected manifest, key IDs/versions and
metadata. Test valid restore, byte-tampered backup, wrong key/secret,
incomplete backup, stale backup and duplicate restore. Never restore
unverified material or allow stale restore to undo revocation.

## 13. Audit ledger

Each event contains: - Event ID and monotonically increasing sequence. -
UTC timestamp and monotonic time where available. - Actor identity from
authenticated server context. - Action, target type/ID, decision/result
and reason code. - Correlation/request/incident IDs. - Policy and key
version (not key material). - Node acknowledgement/evidence
references. - Sanitized structured metadata. - Previous event hash and
current event hash.

Canonical serialization must define field order, encoding and version.
Compute `SHA256(prev_hash || canonical_event_bytes)`. Define a genesis
value. Optionally sign periodic checkpoints using a verified ML-DSA
implementation.

Injection controls: - Structured JSON only; no concatenation of user
text into line-based events. - Normalize/escape CR/LF/control characters
and cap input length. - Actor/action values come from authenticated
context and server-side enums. - One event per record. - Redact tokens,
secrets, keys, shared secrets and plaintext. - Verify sequence, previous
hash and current hash; detect tampering, deletion, reordering and actor
mutation.

## 14. Detection engine --- deterministic, no ML

### 14.1 Input and event time

-   Parse organizer practice labels/data after inspecting exact schemas.
-   Support unknown fields safely.
-   Generate additional synthetic data with a documented seed.
-   Track event timestamp, observed timestamp and source clock offset.
-   Configure bounded reorder window; choose and document a default
    after source review.
-   Use watermarks/late-event handling; mark overlapping uncertainty
    intervals rather than inventing exact order.

### 14.2 Rules

Privilege-change: - Escalation without approved change ticket/authorized
operator. - Self-escalation. - Unexpected admin grant. - Revoked actor
attempts.

Service access: - Actor accesses a service absent from
baseline/window. - Unusual service count in a short window. - Sensitive
service access after privilege change. - Unusual event sequence.

Lateral movement: - Directed graph nodes represent identities/services;
edges represent observed access. - Time-aware rolling paths. - Flag
newly observed multi-hop paths to sensitive targets. - Suppress known
approved maintenance paths only when context supports it. - Alert
includes identity, source/target, path, event IDs/timestamps, rule and
explanation.

### 14.3 Scoring and metrics

Use transparent weighted rules or deterministic severity levels; no
opaque model or "AI risk score".

Calculate: - TP, FP, TN, FN. - Precision = TP / (TP + FP). - Recall = TP
/ (TP + FN). - F1 = 2 × precision × recall / (precision + recall). -
False alerts per 1,000 benign events. - Median and p95 time-to-alert. -
Per-rule breakdown, confusion matrix and ingestion latency.

Guard zero denominators and state the metric convention. Record dataset
version and seed. If labels are absent, report "not evaluated".

## 15. Messaging and session subsystem

-   Synthetic sender and recipient.
-   AEAD-encrypted payload with authenticated message ID, sender,
    recipient, session ID, key version, timestamp/expiry and protocol
    version.
-   Verify recipient binding before decryption.
-   Durable replay ledger or sequence state; reject duplicate IDs and
    sequences.
-   Bounded buffering for reordering; deliver only complete
    authenticated messages after recovery.
-   Drop incomplete/invalid messages with explicit reason.
-   Session resumption token is cryptographically protected,
    expiry-bound and bound to authenticated peer.
-   Same session ID presented by another identity must fail.
-   Message states: sent, encrypted, delivered, failed,
    rejected/replayed, pending recovery.
-   Never log plaintext or key material.

## 16. API design

All mutating endpoints require authorization, validation, audit logging
and correlation ID. Use typed Pydantic schemas, opaque IDs, explicit
errors and no secrets in responses.

### 16.1 API groups

  ------------------------------------------------------------------------------------------
  Group                               Endpoint examples
  ----------------------------------- ------------------------------------------------------
  Health                              `GET /health`

  Auth/demo                           `POST /auth/demo-login`, `POST /auth/logout`,
                                      `GET /auth/session`

  Identity                            `GET /identities`, `GET /identities/{id}`,
                                      role/permission inspection

  Devices                             `GET /devices`, `POST /devices/enroll`,
                                      `POST /devices/{id}/suspend`,
                                      `POST /devices/{id}/revoke`, replacement re-enrolment

  Sessions                            `GET /sessions`, `POST /sessions/{id}/revoke`

  Policy                              `POST /policy/evaluate`

  Resources                           `GET /resources`, `GET /resources/{id}`,
                                      `POST /resources/{id}/read`, optional rotate-key
                                      action

  Keys                                `GET /keys`, `GET /keys/{id}`, `POST /keys/generate`,
                                      `POST /keys/{id}/rotate`, `POST /keys/{id}/revoke`,
                                      rotation status/recover

  Backups                             `POST /keys/backups/create`, `/verify`, `/restore`

  Nodes                               `GET /nodes`, `GET /nodes/{id}`,
                                      `POST /nodes/simulate-latency`, `/simulate-partition`,
                                      `/simulate-recover`, `POST /nodes/reconcile`

  Incidents                           `GET /incidents`, `GET /incidents/{id}`,
                                      lost-device/key-compromise/privilege-change report,
                                      respond/close, receipt

  Messages                            `POST /messages/send`, `GET /messages`,
                                      deliver/resume/simulate-loss/simulate-reorder/verify

  Detector                            `POST /detector/ingest`, `/run`,
                                      `GET /detector/alerts`, `/metrics`, `/rules`, scenario
                                      simulation

  Audit                               `GET /audit/events`, event detail,
                                      `POST /audit/verify`, export, demo-only tamper fixture

  Benchmarks                          `POST /bench/run`, `GET /bench/runs`, run detail and
                                      report

  Evidence                            `GET /evidence/requirements`, `/scorecard`, export

  Simulation                          `POST /simulation/reset`, scenario run and scenario
                                      reset
  ------------------------------------------------------------------------------------------

The uploaded build prompt lists further route examples, including exact
path variants. Before coding, reconcile the final route names with the
current toolkit and API contract and document them in `docs/api.md`.

### 16.2 Standard response conventions

For every mutation: - Return operation/incident ID and correlation ID. -
Return state and evidence references, not secret material. - Return
explicit partial/not-converged status when appropriate. - Make retries
idempotent where safe. - Use structured reason codes for allow/deny and
failure. - Do not return protected body on denial or error.

## 17. Frontend technical requirements

-   React + TypeScript + Vite.
-   Tailwind and consistent accessible component system.
-   TanStack Query for server state and cache invalidation.
-   React Router for navigation.
-   Recharts or equivalent for measured data.
-   Dark theme default, optional light theme.
-   Midnight navy/charcoal, restrained teal/cyan, violet and amber/red
    status accents.
-   Desktop-first for judge laptop; tablet/mobile responsive.
-   Accessible contrast, keyboard support, reduced-motion option.
-   Loading, empty, error and success states.
-   Confirmation dialogs for security/destructive operations.
-   Every action calls backend; no local-only fake toggles.
-   Charts use actual results or explicitly labelled deterministic demo
    data.

### Main pages

1.  Landing.
2.  Synthetic demo login.
3.  Overview.
4.  Identity & Access.
5.  Devices.
6.  Secure Vault.
7.  Key Lifecycle.
8.  Node Control Plane.
9.  Incident Center.
10. Detection & Lateral Movement.
11. Secure Messaging Lab.
12. Audit & Evidence.
13. Benchmark Lab.
14. Attack/Failure Simulation.
15. Requirements Scorecard.
16. Settings/Docs.

## 18. Testing strategy

Tests must be independently derived from requirements, not only from
implementation internals. Include black-box API tests, adapter process
tests, crypto interoperability/known-answer tests and scenario
acceptance tests.

### 18.1 Adapter tests

-   All five operations.
-   Process-per-request persistence.
-   stdin/stdout JSON contract.
-   stdout exactly one JSON object; stderr sanitized.
-   Fresh setup reset.
-   Exact protected body on authorized read.
-   Denial contains no protected value.
-   Owner/peer isolation.
-   Revoke persistence.
-   Audit correlation.
-   Synthetic key marker leakage test.
-   ML-KEM-768/HMAC independent verification.
-   Malformed request and unknown operation.

### 18.2 Authorization/security tests

-   Unknown/disabled actor.
-   Wrong owner.
-   Pending/suspended/revoked device.
-   Expired/revoked session.
-   Session/device mismatch.
-   Peer binding.
-   Self privilege escalation.
-   Unauthorized operator action.
-   Fail-closed policy errors.
-   Revoked key never reactivated.
-   Stale key after cutoff.
-   Signature tamper/wrong signer if signatures implemented.
-   Ciphertext/nonce/AAD tamper.
-   Backup tamper.
-   Audit tamper/delete/reorder/injection.
-   Replay duplicate.
-   Recipient substitution.
-   Cross-peer session resume.
-   No plaintext on decrypt failure.
-   Rate limiting, input validation and secret scanning.

### 18.3 State/recovery tests

-   Rotation success.
-   Crash before/after commit.
-   Crash after revocation.
-   Old key denied after recovery.
-   Node partition and convergence.
-   Retry/idempotency.
-   Concurrent read versus revoke.
-   Valid/invalid/stale backup.
-   Replacement re-enrolment; old device blocked; peer unaffected.
-   Missing/corrupt DB fails safe.

### 18.4 Detector tests

-   Approved admin change benign.
-   Unauthorized/self escalation alert.
-   Normal service path benign.
-   Unusual multi-hop path alert.
-   Sensitive service after suspicious privilege change.
-   New service discovery.
-   Clock offset/reordered/late events.
-   Benign context suppression.
-   Unknown schema/missing fields/malformed rows.
-   No hardcoded actor/service names.
-   Actual metric calculation.

### 18.5 Messaging tests

-   Intended recipient decrypts.
-   Wrong recipient denied.
-   Modified recipient AAD fails.
-   Duplicate replay rejected.
-   Incomplete message discarded.
-   Reordered message recovered or failure explained.
-   Session resumption peer-bound.
-   Forward secrecy test only if supported.
-   No plaintext logs.
-   Invalid ciphertext/signature denied.

### 18.6 Reliability/UI tests

-   Clean DB/migration startup and reset.
-   Offline startup.
-   Typed/documented endpoints.
-   Transaction rollback.
-   Concurrent API requests.
-   Timeout/crash/dependency failure.
-   Safe errors.
-   Frontend main workflow smoke tests and no console errors.
-   Clean install in a new virtual environment.

## 19. Benchmark methodology

Use `time.perf_counter_ns`, warmups, repeated samples and fixed
seeds/configuration. At least 100 samples for lightweight operations;
choose and explain appropriate counts for crypto/file operations. Record
environment and exact versions.

Measure: - Adapter cold start and each operation. - Policy evaluation
and identity/device/session checks. - ML-KEM
keygen/encapsulation/decapsulation. - ML-DSA sign/verify if
implemented. - HKDF. - AES-GCM for 1 KB, 100 KB, 1 MB, 10 MB and 100 MB
where hardware allows. - Audit append/verify at 100, 1,000 and 10,000
events. - Backup verification. - Key rotation and crash recovery. -
Revocation convergence across 3--7 nodes. - Detector ingestion,
throughput, latency and graph scaling. - API P50/P95/P99 and controlled
concurrency. - Message encrypt/decrypt/replay/delivery. - CPU, peak RSS
RAM, startup and test duration.

Output: - `reports/benchmarks/latest.json` - CSV raw samples. -
Human-readable Markdown summary. - Environment, seed, sample count,
success/error count and methodology. - Mean, median/P50, P95, P99,
min/max, standard deviation and throughput. - Graphs only from measured
data.

Engineering goals in the source prompt (not organizer thresholds): local
zero-trust decision p95 \< 50 ms and small-file workflow p95 \< 100 ms
excluding UI rendering. Report only if measured. Adapter must meet the
official validator timeout; do not treat timeout as a performance
target.

## 20. Security and operating controls

-   Strong typing and Pydantic validation.
-   Parameterized DB queries/ORM.
-   Backend authorization on every protected endpoint.
-   Least privilege and separation of duties.
-   Secrets from environment/config; `.env` ignored; `.env.example`
    placeholders only.
-   No hard-coded secrets/private keys.
-   Structured sanitized logging.
-   No secrets/plaintext in traces, analytics, reports or errors.
-   Rate-limit login and sensitive endpoints.
-   Restrict CORS; CSRF protection if cookie auth is used; secure cookie
    flags outside local mode.
-   Validate sizes, strings, paths and opaque IDs; prevent path
    traversal.
-   Bounded memory; stream large files where feasible.
-   Unique AEAD nonces; authenticated metadata; safe plaintext release.
-   Transactional state changes, idempotency and race tests.
-   No external network in judge mode.
-   Never attack systems outside authorized sandbox or run DoS against
    shared services.
-   Do not hide failing tests, skip required tests or fabricate
    benchmark output.
-   Never modify official toolkit files to make validator pass.

## 21. Threat model

### Assets

Synthetic protected files/messages, identities/devices/sessions,
keys/key versions, policies, node trust state, backups, audit evidence
and detector data.

### Threat actors/events

Unauthorized user, finder of lost device, compromised valid identity,
malicious/compromised operator, stale node, replay/tamper/privilege
escalation/lateral-movement attempt, process crash and corrupt storage.

### Trust boundaries

Browser↔backend; adapter process↔persistent state;
identity/device↔policy; control plane↔simulated nodes; key store↔crypto
operations; event ingestion↔audit/detector; sender↔recipient.

### Controls

Server-side authorization, fail-closed decisions, device-bound sessions,
revocation tombstones, monotonic versions, vetted crypto, audit hash
chain/checkpoints, verified backups, bounded detector and offline
simulation.

### Limitations to disclose

No HSM; local hackathon prototype; node simulator is not distributed
consensus; compromised host OS is outside protection; plaintext already
copied cannot be recalled; forward secrecy only if proven; hash chain
alone cannot resist an attacker controlling all storage and signing
authority; OAuth is optional and not required.

## 22. Implementation phases and gates

  ---------------------------------------------------------------------------
  Phase                   Work                        Exit gate
  ----------------------- --------------------------- -----------------------
  0\. Source review       Read current official Track Requirements mapped;
                          4 source, toolkit, adapter  unknowns recorded.
                          docs, starter, validator,   
                          practice labels, evidence   
                          sheet and runtime. Create   
                          traceability, assumptions   
                          and threat model.           

  1\. Adapter first       Build root adapter,         Adapter passes; no
                          persistence and exact five  leakage.
                          operations; add process     
                          tests; run official         
                          validator; add              
                          protected-read interop      
                          test.                       

  2\. Core backend        DB schema/migrations,       Black-box
                          services, typed APIs,       access-control tests
                          policy, synthetic seed and  pass.
                          state machines.             

  3\. Crypto vault        ML-KEM interop, AES-GCM,    KAT/interoperability
                          HKDF, optional ML-DSA, key  and tamper tests pass.
                          metadata/lifecycle.         

  4\. Revocation/nodes    Three-node baseline,        Peer unaffected; all
                          propagation, convergence,   reachable nodes
                          cutoff, partition           enforce; metrics
                          simulation.                 measured.

  5\. Rotation/recovery   Journal, crash injection,   Crash matrix passes.
                          commit recovery, tombstones 
                          and backup verification.    

  6\. Audit/evidence      Canonical ledger, hash      Correlation and tamper
                          chain, verifier, optional   tests pass.
                          checkpoints and             
                          injection/tamper tests.     

  7\. Detector            Practice data parser,       Labelled metrics
                          seeded generator,           measured and explained.
                          deterministic rules, graph  
                          paths, clock                
                          skew/reordering and         
                          metrics.                    

  8\. Messaging           Recipient binding, replay,  Tests pass; limitations
                          delivery/loss/reordering,   explicit.
                          peer-bound resumption and   
                          forward-secrecy status.     

  9\. Frontend            Landing, demo login and all Main workflows and E2E
                          operational pages; connect  smoke tests pass.
                          every control to backend.   

  10\. Hardening          Dependency audit, secret    No unresolved
                          scan, static analysis,      critical/high finding
                          validation, permissions,    identified by project
                          race tests, safe logs,      checks; limitations
                          offline/clean install.      listed.

  11\. Submission         Validator output,           Evidence package
                          tests/coverage, crypto      complete.
                          proof, benchmarks, detector 
                          metrics, convergence        
                          report, threat model,       
                          scorecard, README, brief,   
                          demo and clean install.     
  ---------------------------------------------------------------------------

At each phase: implement → targeted tests → inspect failures → fix →
full regression → update traceability/evidence → commit logically →
report actual status.

## 23. Required scenario runner

Implement one-click resettable scenarios: 1. Normal protected read. 2.
Lost device. 3. Key rotation. 4. Crash recovery at every phase. 5.
Backup corruption. 6. Log injection/tamper. 7. Suspicious privilege
change. 8. Lateral movement. 9. Clock skew/reordering. 10.
Replay/recipient binding. 11. Message loss/reordering. 12. Session
resumption. 13. Audit evidence verification. 14. Performance benchmark.

Every scenario result includes scenario ID, timestamps, steps, status,
assertions, failed checks, linked audit IDs, latency and explanation.
Status values are `PASS`, `FAIL`, `PARTIAL`, `NOT RUN`; skipped
assertions prevent PASS.

## 24. Submission checklist

-   [ ] Public repository created during the event.
-   [ ] One root toolkit entry point.
-   [ ] Exact adapter contract implemented.
-   [ ] Official local validator output captured.
-   [ ] Independent ML-KEM-768/HMAC interoperability test captured.
-   [ ] Pinned dependency list and clean setup README.
-   [ ] Tests and actual coverage report.
-   [ ] Crypto design and threat model.
-   [ ] Requirement traceability CSV and acceptance gates.
-   [ ] Actual benchmark JSON/CSV/Markdown.
-   [ ] Detector metrics and dataset/seed details.
-   [ ] Revocation convergence report.
-   [ ] Known limitations and security findings.
-   [ ] Two-page project brief PDF.
-   [ ] Five-minute demo recording/link embedded as fallback.
-   [ ] Clean-machine setup verification.
-   [ ] No secrets, private keys, real PII or unlicensed copied data in
    repository.

## 25. Source references and implementation caveat

This TRD follows `QSHIELD_Master_Build_Prompt.pdf` (26 pages),
especially its toolkit contract, modular-monolith architecture, crypto
requirements, zero-trust checks, node convergence, recovery, audit,
deterministic detector, messaging, API/UI, test plan, benchmark
methodology, threat model, build phases, repository structure and demo
scenarios. `Yugaantar DevForge Tracks.pdf` establishes the broader Track
4 challenge context. Before implementation, inspect the current official
toolkit and current Track 4 source; where exact schemas, runtime limits
or validator behavior differ, the organizer's current materials take
precedence.

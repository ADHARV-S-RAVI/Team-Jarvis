# Q-SHIELD — Antigravity Stage-by-Stage Build Prompts

**Project:** Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane  
**Track:** Yugaantar DevForge, Track 4 — “Trust, but verify”  
**Primary USP:** Proof-Carrying Trust Changes

## How to use this document

1. Open the Q-SHIELD project folder in Antigravity.
2. Add `QSHIELD_PRD.md`, `QSHIELD_TRD.md`, and the two source PDFs to the project workspace.
3. Paste the **Global Instructions** once.
4. Run the stages in order. Paste only one stage prompt at a time.
5. Do not move to the next stage until Antigravity reports the current stage's exit gate with actual command output and test results.
6. If Antigravity is interrupted, ask it to read `WORK_LOG.md`, `docs/acceptance_gates.md`, and `docs/requirement_traceability.csv` before continuing.

The source PDF explicitly says to inspect the current official Track 4 PDF, full toolkit, `docs/adapter-v1.md`, starter applications, practice data/labels, evidence sheet, brief template and validator before implementation. Those organizer materials take precedence over assumptions in the PRD/TRD.

---

# 0. Global Instructions — Paste once

```text
You are the senior security architect, staff full-stack engineer, cryptography engineer, QA lead and DevOps engineer for Q-SHIELD, a Yugaantar DevForge Track 4 hackathon project.

Your task is to BUILD, RUN, DEBUG, TEST, BENCHMARK and DOCUMENT the working project. Do not stop at plans, scaffolding, mockups or a static dashboard.

PROJECT
Name: Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane.
USP: Proof-Carrying Trust Changes. Every important revoke, rotate or re-enrol operation must be enforced, measured across simulated nodes and accompanied by verifiable evidence: actor, policy decision, state transition, node acknowledgements, convergence timing, verification results and audit-chain reference.

SOURCE OF TRUTH
Read the attached QSHIELD_PRD.md, QSHIELD_TRD.md, QSHIELD_Master_Build_Prompt.pdf and Yugaantar DevForge Tracks.pdf. Then inspect the actual current organizer toolkit and official Track 4 materials if they are available in the workspace. The current organizer contract, adapter-v1.md, starter and validator override assumptions in project documents. Never invent an organizer requirement or adapter schema.

NON-NEGOTIABLE RULES
- No AI/ML model, ML inference, LLM, embeddings, model API or AI API in the submitted runtime. Deterministic rules, statistics and graph logic only.
- Use synthetic identities and synthetic data only. Work only in the authorized organizer sandbox. Never test against other teams or external systems. Never run DoS tests against shared services.
- No custom cryptographic primitives. Use vetted, verified library APIs and test vectors.
- No hard-coded secrets. Never expose keys, shared secrets, private keys, tokens or protected content in logs, errors, UI evidence or unauthorized responses.
- Offline-first, CPU-first judge mode. No cloud dependency or external API requirement.
- Use a modular monolith plus a deterministic local simulator of 3–7 nodes. Clearly label nodes as simulated; do not claim physical distributed infrastructure or consensus.
- Never claim “quantum secure”, “production-ready”, “tamper-proof”, “zero vulnerabilities” or “forward secrecy” unless the specific claim is implemented and proven. If forward secrecy is not proven, say so clearly.
- Do not fabricate tests, validator output, benchmark results, detector metrics or coverage. Only mark PASS when executed and verified.
- Do not modify organizer toolkit/validator files to make tests pass.
- Keep the root toolkit adapter as exactly one entry point: track4_service.py, unless the official source proves a material reason to use another language/entry point.
- The adapter must not depend on the frontend or require an external service.

WORKING METHOD
For every stage:
1. Inspect existing files and current state before editing.
2. Implement the stage fully, not just scaffold it.
3. Run focused tests.
4. Inspect failures and fix them.
5. Run relevant regression tests.
6. Update documentation, traceability and acceptance-gate status.
7. Update WORK_LOG.md with files changed, commands run, actual results, failures/fixes and remaining blockers.
8. Report the exit gate honestly.
Do not ask me to approve every routine engineering decision. Choose the safest simple option where the source is silent, document it in docs/assumptions_and_open_questions.md and continue. Ask only if a genuinely blocking organizer decision cannot be resolved from the files.

PROJECT CONTINUITY
Maintain:
- WORK_LOG.md
- docs/source_requirements.md
- docs/requirement_traceability.csv
- docs/assumptions_and_open_questions.md
- docs/acceptance_gates.md
- docs/limitations.md

Before starting any new stage, read these files and inspect git status. Avoid overwriting working code from previous stages. Do not create duplicate modules or competing implementations. Keep API contracts stable once agreed.

At the end of each stage, output:
- What was implemented
- Files created/changed
- Commands executed
- Tests and actual results
- Acceptance gates passed/failed/not run
- Remaining blockers
- Exact next stage recommendation

Begin by confirming the project files and source materials available in the workspace. Do not start coding until Stage 0 has completed.
```

---

# Stage 0 — Source Review, Repository Inspection and Implementation Baseline

```text
STAGE 0 — SOURCE REVIEW AND BASELINE

Do not implement application features yet.

1. Inspect the entire current project workspace and git status. Identify whether this is an existing repository or a new folder. Preserve existing user work.
2. Read QSHIELD_PRD.md and QSHIELD_TRD.md fully.
3. Read QSHIELD_Master_Build_Prompt.pdf and Yugaantar DevForge Tracks.pdf fully, especially the Track 4 requirements and all adapter, architecture, crypto, testing, UI, benchmark, submission and agent-workflow sections.
4. Search the workspace for the actual organizer toolkit and inspect, if present:
   - current official Track 4 problem statement
   - complete toolkit repository
   - docs/adapter-v1.md
   - Python/Node starter and demo applications
   - practice data and labels
   - evidence sheet and two-page brief template
   - validator source and commands
   - runtime/dependency versions and filesystem constraints
5. Do not assume these files exist. If missing, list exactly what is missing and proceed only with source-backed facts. Do not fabricate schemas or validator behavior.
6. Create:
   - docs/source_requirements.md — requirement ID, source wording/paraphrase, page/section, required evidence and implementation mapping.
   - docs/requirement_traceability.csv — requirement → module → API/UI → test ID → evidence artifact.
   - docs/assumptions_and_open_questions.md — facts, assumptions, decisions and unresolved questions.
   - docs/acceptance_gates.md — gates G0 onward with status NOT RUN initially.
   - docs/architecture.md — modular monolith and separate toolkit adapter architecture.
   - docs/limitations.md — explicit prototype limitations.
   - WORK_LOG.md — Stage 0 status and evidence.
7. Derive a prioritized build sequence with adapter compatibility first. Preserve all 12 Track 4 goal areas: rotation, cross-node revocation, crash recovery, backup integrity, log integrity, contextual privilege detection, lateral movement, clock skew/reordering, replay/recipient binding, forward secrecy status, loss/reordering delivery and peer-bound session resumption.
8. Confirm the proposed stack against the actual runtime before pinning versions: Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, SQLite, pqcrypto, cryptography, React, TypeScript, Vite and Node. Treat versions in the source as constraints to verify, not as permission to guess APIs.
9. Do not create fake implementation files or empty feature modules.

EXIT GATE:
- Source inventory complete.
- G0 source alignment documented.
- All 12 goals mapped to tests/evidence.
- Unknown organizer/toolkit details explicitly listed.
- No application implementation started prematurely.

Report the findings and stop.
```

# Stage 1 — Exact Toolkit Adapter (Highest Priority)

```text
STAGE 1 — TOOLKIT ADAPTER FIRST

Implement the organizer-compatible adapter before the dashboard or broad backend.

First re-read docs/source_requirements.md, docs/assumptions_and_open_questions.md and the actual adapter-v1.md/starter/validator. Use the exact official JSON schema and response behavior. If the official toolkit is absent, implement only the source-backed contract in the master prompt and mark organizer validation BLOCKED/NOT RUN.

Requirements:
- Exactly one root entry point: track4_service.py, unless the official source requires otherwise.
- One UTF-8 JSON object from stdin to EOF.
- Exactly one JSON object on stdout. Diagnostics only on stderr.
- New process per request; state must persist in the organizer-provided writable path. Use TRACK4_STATE_DIR when present; otherwise follow the official OS temporary path requirement.
- No dependency on frontend, network or cloud.
- Persist mutations before acknowledging success.
- Keep key_material, shared secrets and protected content out of logs and unintended output.
- Treat IDs as opaque strings.

Implement the five exact operations:
1. setup: initialize/reset owners mapping, exact content strings, disabled actor IDs and synthetic key material. Return {"ready": true} only after durable setup.
2. read: owner gets exact stored body; denied response is {"decision":"deny"} with no body, snippet or content-bearing metadata.
3. revoke: persist actor revocation before success; do not affect other actors.
4. audit: request_id returns the exact recorded request ID and decision; input text must not forge actor/action/event boundaries.
5. protected_read: authorize first; parse standard Base64 raw ML-KEM-768 public key; use vetted pqcrypto API; return standard Base64 KEM ciphertext and lowercase-hex HMAC-SHA-256 over UTF-8 challenge + exact stored body, with no separator. Keep shared secret internal.

Do not guess pqcrypto method names or sizes. Inspect installed package/version and verify actual API. Never substitute custom crypto.

Add independent process-level tests:
- setup and reset
- owner exact read
- peer owner exact read
- wrong owner denied with no body
- revoke persists across fresh process
- revoked actor denied
- unaffected peer remains allowed
- audit correlation
- protected_read independently decapsulates and verifies HMAC
- malformed Base64/key/challenge safely rejected
- synthetic key marker absent from stdout/stderr
- exactly one valid JSON object on stdout
- clean exit/no process leftovers

Run the official validator if present. Do not modify it. Save exact command and actual output under reports/evidence/ or reports/test_report/.

EXIT GATE:
- Adapter contract tests pass.
- Fresh-process persistence passes.
- Protected-read interop passes independently.
- Official validator result recorded, or clearly marked BLOCKED because official validator is unavailable.
- No secret/content leakage tests fail.
- Update traceability, acceptance gates and WORK_LOG.md.
Do not proceed to dashboard work if this gate has unresolved critical failures.
```

# Stage 2 — Backend Foundation, Database and Zero-Trust Authorization

```text
STAGE 2 — BACKEND FOUNDATION AND ACCESS CONTROL

Build the local backend as a modular monolith. Keep the Stage 1 adapter stable and reuse its domain logic where appropriate; do not create a second adapter.

Stack, after runtime verification:
- Python 3.12
- FastAPI and Pydantic v2
- SQLAlchemy 2 and Alembic
- SQLite with foreign keys, transactions, suitable busy timeout and WAL where appropriate
- pytest, HTTPX/TestClient

Implement:
- app configuration and environment validation
- health and readiness endpoints
- database initialization and migrations from an empty database
- typed request/response schemas
- correlation IDs and consistent safe errors
- synthetic demo authentication (no mandatory OAuth or internet)
- actors/users, roles and permissions
- identity, device and session domain models
- resources and ownership/permission model
- backend authorization service
- structured audit integration hooks
- deterministic demo seed and reset command

Authorization must run server-side for every protected request in this order:
1. valid request
2. identity exists and enabled
3. authenticated session exists and is bound to actor
4. session not expired/revoked
5. device belongs to actor and is trusted/enrolled/not revoked
6. actor has permission
7. resource exists and is enabled
8. key version is active and not revoked/compromised
9. incident/policy does not deny
Unknown/error/inconsistent state must fail closed.

Implement API groups using a consistent /api/v1 prefix. Start with health, auth/demo, users/roles, devices, sessions, resources and policy evaluation. Document exact routes in docs/api.md.

Security tests:
- unknown/disabled actor
- wrong owner
- pending/suspended/revoked device
- expired/revoked session
- actor/device/session mismatch
- peer binding
- unauthorized operator action
- self privilege escalation
- policy/database failure fails closed
- no protected content in deny/error responses
- migration from empty DB and reset seed

EXIT GATE:
- Backend starts offline.
- Migrations work from empty state.
- All authorization invariants have independent tests.
- Every protected endpoint uses backend authorization.
- Adapter regression remains green.
- Update docs, traceability, acceptance gates and WORK_LOG.md.
```

# Stage 3 — Cryptographic Provider and Protected Vault

```text
STAGE 3 — CRYPTO PROVIDER AND SECURE VAULT

Implement crypto only through vetted libraries. First inspect installed versions and verify exact APIs, supported parameter sets and test vectors. Do not invent APIs or hand-roll primitives.

Required:
- ML-KEM-768 for adapter protected_read and PQC shared-secret establishment.
- AES-256-GCM (or a vetted alternative only if official environment compatibility requires it) for resource/message encryption.
- HKDF-SHA-256 for purpose-separated key derivation.
- HMAC-SHA-256 exact protected_read proof.
- SHA-256 for audit/backup integrity metadata.
- OS cryptographic randomness.
- ML-DSA only if verified library support, parameter level and test vectors are available; otherwise document as deferred.

Implement:
- backend/app/crypto provider facade
- crypto startup self-test
- resource envelope encryption with a random DEK per resource
- key-purpose separation for KEM, identity, resource DEK, session and audit signing
- authenticated metadata/AAD binding schema version, resource/message ID, sender/recipient where applicable, key version, algorithm, timestamp/expiry and session ID
- safe key metadata and version handling; never expose raw keys in API/UI/logs
- protected vault read/write path
- docs/crypto_design.md with algorithm, purpose, parameters, library/API/version, lifecycle, test vectors, limitations and flow diagram

AES-GCM rules:
- Never reuse a nonce with the same key.
- Do not release plaintext until authentication succeeds.
- Ciphertext, nonce or AAD tampering must fail closed.
- Denial and decrypt failure must not return plaintext.

Add independent interoperability/known-answer tests and benchmark crypto operations. Verify protected_read independently decapsulates and recomputes the exact HMAC.

Do not claim forward secrecy based only on ML-KEM or ordinary key derivation.

EXIT GATE:
- Crypto APIs verified against installed versions.
- ML-KEM-768/HMAC adapter interoperability passes.
- AEAD tamper tests pass.
- No plaintext/key leakage.
- Crypto design and limitations documented.
- Stage 1 and Stage 2 regressions pass.
```

# Stage 4 — Device Lifecycle, Sessions and Lost-Device Incident

```text
STAGE 4 — DEVICE AND SESSION LIFECYCLE

Implement the full synthetic device/session lifecycle and lost-device response.

Device requirements:
- Enrol, suspend, restore only when policy allows, revoke and replacement re-enrol.
- Store owner, credential fingerprint, lifecycle state/version and timestamps; do not store reusable raw credentials unnecessarily.
- A revoked credential/device must never be reactivated.
- Replacement device enrolment must not restore trust to the old device.

Session requirements:
- Opaque session identifiers/tokens; store token hashes where appropriate.
- Bind sessions to actor, device and authenticated peer.
- Expiry and revocation enforced on every protected request.
- Logout/session invalidation must take effect immediately.
- A different identity must not inherit a session by reusing a session ID.

Lost-device workflow:
1. Authorized operator reports loss with reason.
2. Backend verifies operator authority and confirmation.
3. Commit revocation tombstone and central deny before success.
4. Trigger node propagation (node implementation may be completed in Stage 5; expose a clear integration boundary now).
5. Owner enrols replacement device.
6. Old device remains denied.
7. Unaffected authorized peer retains access.
8. Produce incident record and evidence references.

Add APIs, schemas, audit events and tests. Add UI only if an existing backend test console is needed; do not build the full dashboard yet.

EXIT GATE:
- Lost-device and replacement workflow tests pass.
- Old device remains denied after restart.
- Other authorized peer retains access.
- Session expiry/revocation/peer-binding tests pass.
- No unauthorized user can perform operator actions.
- Update evidence and WORK_LOG.md.
```

# Stage 5 — Key Lifecycle, Rotation and Simulated Node Convergence

```text
STAGE 5 — KEY ROTATION AND MULTI-NODE REVOCATION

Implement the key lifecycle state machine and deterministic 3–7 node simulator.

Key state requirements:
PREPARED → ACTIVE → ROTATING → ACTIVE_NEW.
Previous key becomes RETIRED or REVOKED according to documented policy.
COMPROMISED is terminal. REVOKED and COMPROMISED keys can never be reactivated.

Rotation phases:
1. PREPARE: generate/verify new key metadata and prepare backup/journal.
2. DISTRIBUTE: stage new version to nodes and collect acknowledgements.
3. COMMIT: atomically update active-version pointer/epoch.
4. RETIRE: deny old key after cutoff and record retirement/revocation.

Policy:
- Default zero grace period for new requests after commit/cutoff.
- Explicitly define how authorized transfers already in progress are handled. They may finish only if explicitly classified as in-flight and policy allows.
- No new request can use old key after cutoff.
- Any optional grace simulation must be disabled by default and precisely documented.

Node simulator:
- At least 3 nodes; configurable 3–7.
- Each node has ID/service, accepted key version, revoked actor/device/key state, sequence/epoch, health, delay, acknowledgement/enforcement timestamps and fault state.
- Central revocation tombstone is durable before acknowledgement; central policy denies immediately.
- Propagation is idempotent and monotonic; stale updates cannot undo revocation.
- Simulate latency, node partition and recovery only locally.
- An unreachable node must show NOT CONVERGED. Never claim success prematurely.
- New requests at revoked nodes are denied.
- Measure time from revoke start to last node enforcement.

Metrics:
- per-node enforcement delay
- nodes converged / total
- convergence p50/p95/p99/max over actual runs
- old-key post-cutoff acceptance count (target zero)
- unaffected peer access success
- replacement-device success and old-device denial

Add race tests for read versus revoke, stale update tests, retry/idempotency tests and node restart tests. Create an incident receipt linking actor, policy decision, state transition, node acknowledgements, convergence timing, verification results and audit reference.

EXIT GATE:
- Rotation state machine and cutoff tests pass.
- All reachable nodes enforce revocation.
- Partition is honestly reported as not converged.
- No stale update restores trust.
- Revoked key never reactivates.
- Convergence metrics are measured, not hard-coded.
- Update docs and regression suite.
```

# Stage 6 — Crash Recovery, Rotation Journal and Backup Integrity

```text
STAGE 6 — CRASH RECOVERY AND BACKUP INTEGRITY

Implement durable rotation journal, crash injection and verified backup/restore.

Journal fields:
- operation ID
- previous/proposed key versions
- phase
- committed flag
- actor/reason
- integrity hash
- timestamps
- evidence references

Recovery semantics:
- Crash before commit: recover previous authorized version unless a newer revocation supersedes it.
- Crash after commit: recover new committed version.
- Revoked/compromised keys remain revoked in every recovery path.
- Tombstones survive restart and stale snapshots.
- Inconsistent state fails closed.
- Each phase and recovery action must be idempotent.

Crash injection points:
- after prepare
- after backup
- after node 1/2 acknowledgement
- before commit
- immediately after commit
- during retirement
- after revocation tombstone

Backup:
- integrity-protected manifest, key IDs/versions and metadata
- use authenticated/encrypted or signed manifest as appropriate to verified library support
- verify before restore
- reject byte tampering, wrong key/secret, incomplete backup and stale backup
- stale restore must not undo a newer revocation
- duplicate restore must be idempotent
- never restore unverified key material

Create a crash matrix report showing each injection point, expected recovery state, actual result and evidence reference. Do not treat SQLite as distributed consensus; describe its actual durability limits.

EXIT GATE:
- Every required crash injection point has a test.
- Pre-commit and post-commit recovery semantics pass.
- Revocation tombstones survive all tested recovery paths.
- Corrupt, wrong-key, incomplete and stale backups are rejected.
- Committed protected data remains available to authorized users.
- Report exact test results and limitations.
```

# Stage 7 — Append-Only Audit, Integrity Verification and Receipts

```text
STAGE 7 — AUDIT LEDGER AND PROOF-CARRYING EVIDENCE

Implement the append-only structured audit ledger.

Each event must contain:
- event ID and monotonic sequence
- UTC timestamp and monotonic time where available
- actor from authenticated server context, never from untrusted text
- action, target type/ID, decision/result and reason code
- correlation/request/incident IDs
- policy/key version, never key material
- node acknowledgement/evidence references
- sanitized structured metadata
- previous hash and current hash

Define canonical serialization, version, encoding, genesis value and hash algorithm in docs. Compute SHA-256 over previous hash concatenated with canonical event bytes.

Protect log boundaries:
- structured JSON records only
- escape/normalize CR/LF/control characters and cap text length
- actor/action fields from authenticated context and server-side enums
- one event per record; user text cannot inject a second event or change actor
- redact secrets, tokens, private keys, shared secrets and plaintext
- export sanitized records only

Verifier must detect:
- event modification
- deletion
- reordering
- actor mutation
- boundary/log injection
- broken sequence/previous-hash link

Optional signed checkpoints may use ML-DSA only after library/API/test-vector verification. If unavailable, do not fake signatures. Document the trust/anchoring limitation: a local hash chain alone cannot defeat an attacker controlling all storage and signing authority.

Implement:
- searchable audit events and event details
- chain verification endpoint/CLI
- correlation timeline
- sanitized JSON export
- demo-only non-destructive tamper fixture
- proof-carrying incident receipts linked to audit chain and node evidence

EXIT GATE:
- Valid chain verifies.
- Every tamper/delete/reorder/actor/boundary test is detected.
- User-controlled text cannot forge actor/action/event boundaries.
- No secret/plaintext leakage.
- Receipts link to real events and state changes.
```

# Stage 8 — Explainable Detection and Lateral-Movement Analysis (No ML)

```text
STAGE 8 — DETERMINISTIC DETECTION ENGINE

Implement deterministic rules, statistics and time-aware graph analysis only. AI/ML libraries, inference, embeddings and model APIs are prohibited in the submitted runtime.

First inspect the actual organizer practice dataset and label schemas if available. Do not assume column names or labels. Do not hard-code hidden-test identities, names, IDs, event strings or file paths.

Build:
- schema-flexible validated event parser
- deterministic synthetic event generator with documented seed
- separate labelled fixtures and expected results
- privilege-change detector
- service-access anomaly rules
- time-aware identity/service graph for lateral movement
- clock-offset and out-of-order handling
- explainable alert records and evaluation metrics

Detect:
- escalation without approved ticket/authorized operator
- self-escalation
- unexpected admin grant
- revoked actor attempts
- unusual service access/count/sequence
- sensitive service access after privilege change
- unusual multi-hop path to sensitive service, even with valid credentials

Context:
- approved change window
- operator authorization
- maintenance event
- actor role
- service criticality
- deterministic historical counts/baseline

Lateral-movement alert must show identity, source/target services, graph path, event IDs/timestamps, rule ID and explanation. Approved known paths may be suppressed only with explicit supporting context.

Clock handling:
- store event time, observed/ingest time and source offset where available
- configurable bounded reorder window
- watermarks and late-event handling
- mark order uncertain when intervals overlap
- document supported timing range
- never invent exact order

Metrics on labelled data:
- TP, FP, TN, FN
- precision, recall, F1
- false alerts per 1,000 benign events
- median and p95 time-to-alert
- per-rule breakdown and confusion matrix
- ingestion/processing latency
- dataset version and seed

If labels are missing, report NOT EVALUATED. Do not fabricate results. Add tests for benign approved admin activity, suspicious privilege changes, valid-credential lateral movement, new service names, clock skew, reordered/late events and malformed input.

EXIT GATE:
- No ML/AI runtime dependency.
- Required labelled scenarios are evaluated.
- Metrics are computed from actual fixture/dataset results.
- Alerts include rule/path/evidence explanation.
- Clock uncertainty is represented honestly.
- Update reports/detector and traceability.
```

# Stage 9 — Secure Messaging, Replay Protection and Session Resumption

```text
STAGE 9 — SECURE MESSAGING AND SESSION SECURITY

Implement the local synthetic messaging lab, separate from toolkit protected_read.

Requirements:
- synthetic sender and recipient identities
- vetted AEAD encryption
- authenticated AAD binds protocol/schema version, message ID, sender, recipient, session ID, key version, timestamp/expiry and algorithm
- only intended recipient can decrypt
- recipient modification must fail authentication
- durable replay ledger or sequence state
- duplicate message IDs and repeated authenticated sequence rejected
- loss/reordering simulation with bounded buffer/sequence policy
- only complete authenticated messages delivered after recovery
- incomplete/invalid messages discarded with explicit reason
- session-resumption token protected, expiry-bound and bound to authenticated peer
- different identity cannot inherit session by reusing session ID
- statuses: sent, encrypted, delivered, failed, rejected/replayed, pending recovery
- never log plaintext or key material

Forward secrecy:
- Use only a vetted protocol/library with ephemeral exchange and session evolution/ratcheting if available and verified.
- Do not invent a ratchet or claim that ML-KEM by itself proves forward secrecy.
- If a defensible implementation cannot be completed, explicitly mark forward secrecy NOT ESTABLISHED in UI, docs and scorecard.

Tests:
- intended recipient succeeds
- wrong recipient fails
- modified recipient/AAD fails
- duplicate replay rejected
- incomplete message discarded
- reordered message recovered or failure explained
- cross-peer session resumption denied
- no plaintext on authentication failure
- forward secrecy test only if supported by actual design

EXIT GATE:
- Recipient binding, replay and peer-binding tests pass.
- Loss/reordering recovery behavior is tested.
- No plaintext/key leakage.
- Forward-secrecy status is truthful and evidence-backed.
```

# Stage 10 — Frontend Operator Console and Scenario Runner

```text
STAGE 10 — BUILD THE REAL DASHBOARD

Only now build the complete UI, connected to the existing backend. Do not replace backend security logic with frontend state or mock-only controls.

Stack after version verification:
- React + TypeScript + Vite
- Tailwind and accessible shadcn-style components
- TanStack Query
- React Router
- Recharts or equivalent for real measured data

Design:
- premium cybersecurity product, not generic admin template
- dark theme default, optional light
- midnight navy/charcoal, restrained teal/cyan, violet and amber/red status accents
- subtle borders, technical typography, accessible contrast
- responsive desktop-first, tablet and mobile
- keyboard accessibility and reduced-motion option
- proper loading, empty, error and success states
- confirmation dialogs for destructive/security actions
- no fake charts; use actual backend data or clearly labelled deterministic demo data

Pages:
1. Public landing — “Trust changes. Security follows.”
2. Synthetic demo login
3. Overview dashboard — actual KPIs, event timeline, node convergence, incidents, health and last measured benchmark
4. Identity & Access
5. Devices and lost-device workflow
6. Secure Vault
7. Key Lifecycle and rotation
8. Node Control Plane / Revocation Convergence Map
9. Incident Center and proof receipts
10. Detection & Lateral Movement
11. Secure Messaging Lab
12. Audit & Evidence
13. Benchmark Lab
14. Attack/Failure Simulation
15. Requirements Scorecard
16. Settings/Docs

UX rules:
- Every action calls a real backend endpoint.
- Demo scenarios are visibly labelled SIMULATION and resettable.
- Security actions require authorized actor, reason and confirmation.
- Decision panels show reason code, checks passed/failed and evidence links.
- Tables support search/filter/sort/pagination.
- Detail pages use tabs and timelines.
- Unreachable nodes show NOT CONVERGED, never green success.
- Forward secrecy shows PROVEN only if tests support it; otherwise NOT ESTABLISHED.
- Requirements scorecard links each goal to test/evidence/status/limitation.

Build frontend smoke tests for the main workflows and verify there are no browser console errors. Do not add fake OAuth or require cloud login.

EXIT GATE:
- All listed pages render and are navigable.
- Main security actions call backend and persist.
- Lost-device, rotation, recovery, audit and scenario workflows work end-to-end.
- No UI-only fake security controls.
- Responsive and accessibility smoke tests pass.
```

# Stage 11 — Integration, Independent Security Review and Benchmarks

```text
STAGE 11 — FULL INTEGRATION AND HARDENING

Act as an independent reviewer. Do not assume prior implementation is correct.

1. Read all requirements, traceability, acceptance gates, WORK_LOG and limitations.
2. Inspect the complete diff and repository structure.
3. Run clean installation from pinned dependencies in a fresh environment.
4. Run database migrations from empty state and deterministic reset.
5. Run official adapter validator without modifying it.
6. Run all adapter, crypto, security, recovery, detector, messaging, integration and frontend tests.
7. Run secret scanning, dependency checks, static checks and safe logging checks.
8. Inspect authorization on every protected endpoint.
9. Test concurrency/races around read versus revoke and rotation.
10. Verify offline mode: no runtime external network requirement.
11. Check no AI/ML/model runtime dependency exists.
12. Check no secrets, private keys, real PII or unlicensed copied data are committed.
13. Check error responses and logs for content/key/token leakage.
14. Fix issues, rerun affected tests, then rerun full regression.

Benchmark with perf_counter_ns, warmups, repeated samples and documented environment:
- adapter cold start and each operation
- policy evaluation and identity/device/session checks
- ML-KEM keygen/encapsulation/decapsulation
- ML-DSA only if implemented
- HKDF and AES-GCM at relevant sizes
- audit append/verify
- backup verification
- rotation and crash recovery
- revocation convergence across 3–7 nodes
- detector ingestion/throughput/latency/graph scaling
- API P50/P95/P99 and controlled concurrency
- messaging encrypt/decrypt/replay/delivery
- startup, CPU, peak RAM and test duration

Save actual raw samples and summary:
- reports/benchmarks/latest.json
- raw CSV samples
- Markdown summary with environment, versions, seed, sample count, errors, mean, median/P50, P95, P99, min/max, standard deviation and throughput

Detector metrics must use labelled data. Revocation convergence must use actual timestamps. Never fabricate results or silently omit failed cases.

EXIT GATE:
- Clean install succeeds.
- All mandatory tests and validator results recorded.
- Security review findings documented and fixed or clearly listed.
- Actual benchmark reports saved.
- No critical unresolved issue is hidden.
```

# Stage 12 — Submission Package, Demo and Final Verification

```text
STAGE 12 — SUBMISSION-READY PACKAGE

Prepare the final reproducible submission using only verified implementation evidence.

Create/update:
- README.md — project overview, requirements, architecture, setup, offline run, demo accounts, tests, validator and troubleshooting
- dependency lock/pinned dependency files
- docs/architecture.md
- docs/crypto_design.md
- docs/threat_model.md — one-page threat model summary plus detailed version
- docs/limitations.md
- docs/api.md
- docs/benchmark_methodology.md
- docs/acceptance_gates.md
- docs/requirement_traceability.csv
- docs/demo_script.md — five-minute demo
- reports/test_report/ — actual test/coverage results
- reports/benchmarks/ — raw and summary results
- reports/detector/ — actual labelled evaluation
- reports/evidence/ — validator output, crypto interop, convergence and scenario evidence
- two-page Project Brief PDF using organizer template if present

Five-minute demo sequence:
1. Product promise and architecture (30 seconds).
2. Normal authorized read and wrong-owner denial (40 seconds).
3. Lost device, replacement enrolment and unaffected peer (50 seconds).
4. Key rotation, cutoff and node convergence map (60 seconds).
5. Crash recovery and backup tamper rejection (50 seconds).
6. Audit integrity and explainable lateral movement alert (50 seconds).
7. Messaging replay/recipient-binding and honest forward-secrecy status (40 seconds).
8. Evidence scorecard and measured benchmark summary (20 seconds).

Ensure all demo scenarios reset synthetic data and show PASS/FAIL/PARTIAL/NOT RUN honestly. A skipped assertion cannot produce PASS.

Final review:
- Does every one of the 12 Track 4 goal areas map to implementation, tests and evidence?
- Does the adapter exactly match the official contract?
- Is protected_read independently verified?
- Are old/revoked keys denied after cutoff?
- Does the system report non-convergence honestly?
- Are crash and backup recovery safe?
- Can audit tampering and injection be detected?
- Are detector metrics actual and labelled?
- Are recipient binding, replay, loss/reordering and peer-bound resumption tested?
- Is forward secrecy proven or explicitly not established?
- Can the project run offline from a clean setup?
- Are limitations and security findings transparent?

Do not claim submission-ready if any mandatory gate is unverified. Produce a final status table with PASS, FAIL, PARTIAL or NOT RUN and link each row to evidence.

EXIT GATE:
A clean, reproducible, documented project and honest evidence package are ready for team review and organizer submission.
```

---

## Suggested Antigravity execution order

| Order | Stage | Priority |
|---:|---|---|
| 0 | Source review and baseline | Mandatory |
| 1 | Exact toolkit adapter | P0 — do first |
| 2 | Backend, DB and authorization | P0 |
| 3 | Crypto provider and vault | P0 |
| 4 | Devices and sessions | P0 |
| 5 | Rotation and node convergence | P0 |
| 6 | Crash recovery and backups | P0 |
| 7 | Audit and evidence | P0 |
| 8 | Deterministic detector | P1 |
| 9 | Secure messaging | P1 |
| 10 | Frontend dashboard | P1 |
| 11 | Integration, security review and benchmarks | Mandatory |
| 12 | Submission package and demo | Mandatory |

## Important operating advice

- Do not paste all stages into Antigravity at once. Give it one stage, inspect the result, then continue.
- Keep the PRD, TRD and source PDFs in the workspace so Antigravity can refer to them.
- If the agent starts building UI before the adapter is validated, stop it and return to Stage 1.
- If a library API is uncertain, require the agent to inspect the installed package and prove the API with a small test before integrating it.
- If a stage is incomplete, ask it to finish that stage; do not advance just because files were created.
- Keep the organizer's official toolkit unchanged.
- The local node cluster is a simulator, not a real distributed deployment.
- Never accept invented benchmark values, detector scores, validator output or security claims.

# Q-SHIELD --- Product Requirements Document (PRD)

**Track:** Yugaantar DevForge --- Track 4, "Key Identity Guard / Trust,
but verify"\
**Product codename:** Q-SHIELD --- Quantum-Ready Trust & Revocation
Control Plane\
**Document status:** Implementation baseline derived from
`QSHIELD_Master_Build_Prompt.pdf`\
**Version:** 1.0

------------------------------------------------------------------------

## 1. Product summary

Q-SHIELD is an offline-first security control plane prototype for
synthetic identities, devices, keys, sessions, protected resources and
messages. It demonstrates that trust changes are enforced---not merely
logged---across a simulated multi-node environment, and that each
operation produces verifiable evidence.

**Core USP --- Proof-Carrying Trust Changes:** every important revoke,
rotate or re-enrol operation produces an incident receipt containing the
initiating actor, policy decision, state transition, node
acknowledgements, convergence timing, verification results and
audit-chain reference.

The product combines: 1. An exact organizer-toolkit-compatible
protected-resource adapter. 2. A modular local backend and persistent
state store. 3. A deterministic 3--7 node simulator. 4. An operator
console for workflows, simulation, metrics and evidence.

This is a hackathon sandbox prototype. Simulated nodes are not physical
distributed servers. The product must not claim production readiness,
complete quantum security, zero vulnerabilities or forward secrecy
unless independently implemented and proven.

## 2. Problem statement

A compromised identity, lost device, stale key, interrupted rotation or
unusual service-access path can leave a system trusting credentials that
should no longer be trusted. A security dashboard that only displays
events is insufficient: the system must enforce decisions, propagate
revocation, recover consistently after crashes and provide evidence that
the change took effect.

Q-SHIELD addresses this through a central policy and key-lifecycle
control plane, simulated node propagation, cryptographic
protected-resource operations, tamper-evident audit records and
explainable deterministic detection.

## 3. Goals and success outcomes

### 3.1 Product goals

-   Enforce identity, device, session, resource and key authorization on
    the backend.
-   Implement the exact toolkit adapter contract and survive
    process-per-request execution.
-   Revoke identities/devices/keys across all simulated nodes and
    measure convergence.
-   Rotate keys with explicit cutoff/grace semantics and recover safely
    from injected crashes.
-   Detect corrupted backups and refuse to restore unverified key
    material.
-   Preserve audit actor/action/event boundaries and detect ledger
    tampering.
-   Detect suspicious privilege changes and unusual service-to-service
    paths using explainable non-ML logic.
-   Secure demo messaging against recipient substitution and replay;
    model loss/reordering and peer-bound session resumption.
-   Provide a polished dashboard where every action is backed by a real
    backend operation.
-   Produce repeatable tests, benchmark reports, threat model,
    traceability and submission evidence.

### 3.2 Success criteria

The project is successful when: - The official adapter validator passes,
and independent tests verify `protected_read` ML-KEM-768/HMAC
interoperability. - Unauthorized reads return no protected content;
revocation persists across fresh adapter processes. - After the
configured cutoff, old/revoked credentials are rejected; unaffected
authorized peers retain access. - Revocation convergence is measured
from command start to last node enforcement; incomplete convergence is
never reported as success. - Crash-recovery tests preserve the correct
committed key version and never reactivate revoked/compromised keys. -
Tampered or stale backups are rejected. - Audit-chain tampering,
deletion, reordering and injection are detected. - Detector metrics are
calculated from labelled fixtures/data, not fabricated. - Message
recipient changes, duplicates and cross-peer session-resumption attempts
are rejected. - Offline mode works without cloud services, external APIs
or AI/ML runtime components. - All demo scenarios produce linked
evidence and use `PASS`, `FAIL`, `PARTIAL` or `NOT RUN` honestly.

## 4. Users and roles

All identities and records are synthetic.

  --------------------------------------------------------------------------
  Role                    Responsibilities        Permissions (minimum)
  ----------------------- ----------------------- --------------------------
  Owner/User              Access own protected    Read owned resources;
                          resources, manage own   request own
                          replacement-device      recovery/re-enrolment
                          enrolment               

  Security Operator       Respond to lost         Revoke
                          devices, key compromise devices/keys/identities;
                          and incidents           run approved incident
                                                  workflows

  Admin                   Configure demo policies Administrative
                          and system settings     configuration; cannot
                                                  bypass audit

  Auditor                 Inspect evidence and    Read audit, receipts,
                          verify integrity        scorecards and reports; no
                                                  mutation
  --------------------------------------------------------------------------

Role separation and least privilege are mandatory. A user must not
self-escalate. Destructive/security actions require an authorized actor,
reason and confirmation.

## 5. Scope

### 5.1 In scope

1.  **Toolkit adapter:** one root entry point, `track4_service.py`, with
    `setup`, `read`, `revoke`, `audit` and `protected_read`.
2.  **Identity and access:** synthetic users, roles, permissions,
    devices, sessions, policy evaluation and fail-closed decisions.
3.  **Device lifecycle:** enrol, suspend, revoke and replacement-device
    re-enrolment; old device remains denied.
4.  **Protected vault:** synthetic resources, ownership checks,
    encrypted metadata and authorized read flow.
5.  **Key lifecycle:** key inventory by ID/version/state, generation,
    staged rotation, commit, cutoff, revoke and recovery.
6.  **Node control plane:** 3--7 simulated nodes, state propagation,
    latency/partition/recovery simulation and convergence metrics.
7.  **Incidents:** lost device, key compromise and privilege-change
    workflows with receipts.
8.  **Backups/recovery:** journaled rotation, crash injection, integrity
    verification and safe restore.
9.  **Audit/evidence:** append-only structured events, hash chain,
    verifier, optional signed checkpoints and sanitized export.
10. **Detection:** deterministic rules, context-aware privilege-change
    detection, service graph/lateral-path analysis, clock
    skew/reordering and measured metrics.
11. **Secure messaging lab:** authenticated recipient binding, replay
    prevention, delivery recovery, loss/reordering and peer-bound
    resumption.
12. **Benchmark lab:** repeatable timing and resource measurements with
    raw and summary output.
13. **Dashboard:** public landing, synthetic login, overview and
    operational pages.
14. **Submission artifacts:** README, threat model, crypto design,
    traceability, acceptance gates, two-page brief, demo script and
    reports.

### 5.2 Out of scope

-   Attacking systems outside the organizer sandbox or testing against
    other teams.
-   Real patient, customer or employee data.
-   Real production identity-provider integrations as a requirement;
    Google OAuth is optional only when genuinely configured.
-   Cloud dependencies, external APIs or internet access in
    judge/offline mode.
-   AI/ML models, inference, embeddings, LLMs or AI API calls in the
    submitted product.
-   Custom cryptographic primitives.
-   Claiming physical distributed consensus, HSM protection, guaranteed
    quantum security or forward secrecy without proof.
-   Production deployment or a claim of complete security.

## 6. Functional requirements

### FR-01 --- Toolkit adapter compatibility

-   The repository root contains exactly one toolkit entry point:
    `track4_service.py`.
-   The adapter reads one UTF-8 JSON object from stdin to EOF and writes
    exactly one JSON object to stdout.
-   Diagnostics go to stderr. No keys, shared secrets or protected
    content may appear in logs.
-   State persists across fresh processes in the provided writable state
    directory / OS temporary directory.
-   `setup` initializes owners, exact content strings, disabled actors
    and synthetic key material; return ready only after durable
    initialization.
-   `read` allows an authorized owner and returns the exact body; denial
    returns only a deny decision.
-   `revoke` durably revokes the actor before success.
-   `audit` returns the exact request ID and decision correlation.
-   `protected_read` authorizes first, uses vetted ML-KEM-768
    encapsulation with standard Base64 raw public key, and returns
    Base64 ciphertext plus lowercase-hex HMAC-SHA-256 over UTF-8
    `challenge + stored_body` with no separator. Shared secret remains
    internal.
-   Malformed inputs fail safely without leaking protected data.

### FR-02 --- Zero-trust authorization

Every protected request evaluates, in order: input validity; active
identity; valid identity/device-bound session; session
expiry/revocation; trusted device ownership/state; actor permission;
resource state; active non-revoked key version; incident/policy deny.
Unknown or error states fail closed. Backend authorization is
authoritative; frontend state is never sufficient.

### FR-03 --- Identity, device and session lifecycle

-   Maintain synthetic identities and roles.
-   Maintain device owner, state, credential fingerprint and lifecycle
    metadata.
-   Maintain opaque peer-bound sessions with expiry and revocation.
-   Lost-device response revokes the old device, supports owner
    re-enrolment of a replacement and preserves other users' access.
-   Revoked device credentials cannot be reactivated.

### FR-04 --- Key generation and rotation

-   Track key IDs, versions, algorithms and states; never expose key
    material.
-   Use a staged state machine:
    `PREPARED → ACTIVE → ROTATING → ACTIVE_NEW`; old key becomes
    `RETIRED` or `REVOKED` according to policy; `COMPROMISED` is
    terminal.
-   Rotation stages a new key, distributes/acknowledges it, commits the
    active version atomically and enforces the old-key cutoff.
-   Default policy: zero grace period for new requests after
    commit/cutoff. Any optional grace mode must be explicit, disabled by
    default and tested.
-   Authorized in-flight transfers may complete only if explicitly
    classified and policy allows.
-   No rollback or recovery path may reactivate revoked/compromised
    material.

### FR-05 --- Revocation propagation

-   Simulate at least three nodes; allow configuration from 3 to 7.
-   Nodes track accepted key version, revocation tombstones, last
    sequence/event, health and acknowledgement/enforcement time.
-   Central revocation is committed before success and immediately
    denies new local requests.
-   Propagation is idempotent and monotonic; stale updates cannot undo
    newer revocations.
-   Measure per-node delay and total convergence. Unreachable nodes are
    visibly not converged and must not be reported as successful.
-   Display node status and convergence timeline.

### FR-06 --- Crash recovery and backup integrity

-   Journal each rotation with operation ID, previous/proposed versions,
    phase, commit flag, hashes, actor and evidence.
-   Recovery before commit returns to the prior authorized state unless
    a revocation supersedes it; after commit it restores the new
    committed version.
-   Inject crashes at prepare, backup, node acknowledgements, pre/post
    commit, retirement and revocation-tombstone stages.
-   Backups include an authenticated/encrypted or signed manifest and
    integrity metadata.
-   Reject damaged, incomplete, wrong-key and stale backups; stale
    restore must not undo a newer revocation.
-   Restore only verified key material.

### FR-07 --- Audit integrity and evidence

-   Store append-only structured events with event ID, sequence, UTC
    timestamp, actor from authenticated context, action, target, result,
    reason, correlation IDs, policy/key version, sanitized metadata,
    previous hash and current hash.
-   Canonical serialization and hash-chain format are documented.
-   User-controlled text is data, never an actor/action or second event;
    normalize/escape control characters and cap lengths.
-   Never log secrets, tokens, private keys, shared secrets or plaintext
    bodies.
-   Provide chain verification, searchable event details, correlation
    timeline and sanitized export.
-   Optional ML-DSA signed checkpoints may be added only if library
    support and test vectors are verified.

### FR-08 --- Explainable suspicious-activity detection

-   Use deterministic rules/statistics and graph logic only; no ML.
-   Detect unauthorized/self privilege escalation, unexpected admin
    grants, revoked actor attempts and unusual service access.
-   Build a time-aware directed graph of identity/service access and
    flag unusual multi-hop paths to sensitive services, including
    valid-credential lateral movement.
-   Use approved maintenance windows, operator authorization, actor
    role, service criticality and deterministic historical counts as
    context.
-   Support configured clock offsets, bounded reorder windows and
    uncertain ordering flags.
-   Alerts include rule IDs, matched evidence, identity, source/target
    services, event IDs and explanation.
-   Calculate TP/FP/TN/FN, precision, recall, F1, median/p95 alert time
    and false alerts per 1,000 benign events. Report "not evaluated"
    when labels are unavailable.

### FR-09 --- Secure messaging and session security

-   Provide synthetic sender/recipient identities and authenticated
    encrypted message payloads.
-   Authenticate message ID, sender, recipient, session, key version,
    timestamp/expiry and protocol version as associated data.
-   Only the intended recipient may decrypt; recipient alteration fails
    authentication.
-   Persist replay state and reject duplicate message IDs/sequences.
-   Simulate loss/reordering; deliver complete authenticated messages
    after successful recovery and reject incomplete/invalid messages
    with a reason.
-   Session-resumption credentials are expiry-bound and peer-bound;
    another identity cannot inherit a session ID.
-   Forward secrecy is either implemented with a vetted supported
    protocol and proven by tests, or explicitly marked "not
    established."

### FR-10 --- Dashboard and operational UX

All buttons/actions call backend endpoints. Demo simulations are visibly
labelled and resettable. Security actions require
actor/reason/confirmation. Decision panels show reason codes, checks and
evidence links. Tables support search/filter/sort/pagination. Include
loading, empty, error and responsive states.

Required pages: - Landing and synthetic demo login. - Overview: real
KPIs, timeline, node convergence, incidents, system health and last
measured benchmark. - Identity & Access. - Devices and lost-device
workflow. - Secure Vault. - Key Lifecycle. - Node Control Plane. -
Incident Center and receipts. - Detection & Lateral Movement. - Secure
Messaging Lab. - Audit & Evidence. - Benchmark Lab. - Attack/Failure
Simulation. - Requirements Scorecard. - Settings/Docs.

### FR-11 --- Benchmarking

Measure adapter operations, policy/API latency, identity/device/session
checks, KEM operations, optional signatures, HKDF, AES-GCM sizes, audit
append/verify, backup verification, rotation, node convergence, detector
throughput/latency, graph detection, messaging and startup/test
duration. Record environment and dependency versions. Report raw samples
and mean, median/P50, P95, P99, min/max, standard deviation, throughput
and measured CPU/RAM. Never fabricate values.

### FR-12 --- Evidence and submission

Provide requirement traceability, acceptance-gate status, threat model,
crypto design, limitations, README, pinned dependencies, test/coverage
report, validator output, crypto interoperability proof, benchmark
report, detector metrics, convergence report, two-page project brief and
five-minute demo recording/link.

## 7. Non-functional requirements

  -----------------------------------------------------------------------
  ID                                  Requirement
  ----------------------------------- -----------------------------------
  NFR-01                              Offline-first; no external network
                                      required for judging or inference.

  NFR-02                              Python 3.12 toolkit worker
                                      compatibility; verify actual
                                      organizer runtime/toolkit before
                                      pinning.

  NFR-03                              CPU-first; no GPU or AI/ML runtime
                                      dependency.

  NFR-04                              Backend authorization on every
                                      protected endpoint; fail closed.

  NFR-05                              Persistent state, transactional
                                      updates, idempotent operations and
                                      safe crash recovery.

  NFR-06                              No secrets or protected plaintext
                                      in logs, errors, reports or UI
                                      evidence.

  NFR-07                              Parameterized database access,
                                      typed validation, bounded inputs
                                      and safe error handling.

  NFR-08                              Responsive desktop-first UI with
                                      accessible contrast, keyboard use
                                      and reduced-motion support.

  NFR-09                              Reproducible seeded scenarios and
                                      benchmarks; measured results only.

  NFR-10                              Clear separation between real local
                                      backend behavior and simulated node
                                      behavior.

  NFR-11                              Maintainable modular monolith;
                                      avoid microservices/cloud
                                      infrastructure during the
                                      hackathon.

  NFR-12                              Original code created during the
                                      event; attribute third-party
                                      libraries.
  -----------------------------------------------------------------------

## 8. Product workflows

### Workflow A --- Lost device

1.  Owner's trusted device accesses an owned synthetic resource.
2.  Authorized operator opens a lost-device incident, supplies reason
    and confirms.
3.  Backend commits revocation tombstone and denies new requests.
4.  Node simulator propagates revocation and records acknowledgements.
5.  Dashboard shows per-node status and measured convergence.
6.  Owner enrolls a replacement device.
7.  Old device remains denied; unaffected peer retains access.
8.  Incident receipt links decision, node states, timings and audit
    evidence.

### Workflow B --- Key rotation

1.  Operator starts rotation.
2.  New key material is generated through vetted APIs and marked
    prepared.
3.  Backup/journal is created and verified.
4.  Nodes stage the new version and acknowledge.
5.  Atomic commit advances active version and cutoff.
6.  Old key is rejected after cutoff; new key is accepted.
7.  Rotation receipt and audit evidence are produced.

### Workflow C --- Crash recovery

1.  Select a documented rotation phase for crash injection.
2.  Stop the operation at that point.
3.  Restart/recover from journal and node state.
4.  Verify committed-version semantics and revocation tombstones.
5.  Confirm protected data remains available to authorized users and old
    revoked credentials remain denied.

### Workflow D --- Audit tampering

1.  Run a benign or suspicious event scenario.
2.  Inspect the structured event and correlation.
3.  Use a demo-only non-destructive fixture to alter a record.
4.  Run chain verification.
5.  Show the failing sequence/hash and evidence reference.

### Workflow E --- Secure messaging

1.  Sender composes a synthetic message for a selected recipient.
2.  Backend encrypts and binds recipient/session metadata.
3.  Intended recipient decrypts successfully.
4.  Run wrong-recipient, modified-recipient, duplicate replay and
    loss/reorder tests.
5.  Show status and rejection reasons; do not show plaintext in logs.

## 9. Required demo scenarios

All scenarios reset synthetic data and return scenario ID, start/end,
steps, status, assertions, failed checks, linked audit IDs, latency data
and explanation.

1.  Normal protected read: owner allow, own peer allow, wrong owner
    deny.
2.  Lost device and replacement re-enrolment.
3.  Key rotation and old-key cutoff.
4.  Crash at each rotation phase.
5.  Backup corruption.
6.  Log injection and tamper.
7.  Benign approved administration versus suspicious privilege
    escalation.
8.  Valid-credential lateral movement.
9.  Clock skew and out-of-order events.
10. Replay and recipient binding.
11. Message loss/reordering.
12. Session resumption bound to original peer.
13. Audit chain verification.
14. Actual benchmark run.

Scenario statuses: `PASS`, `FAIL`, `PARTIAL`, `NOT RUN`. A scenario
cannot pass if an assertion was skipped.

## 10. Prioritization

### P0 --- Submission-critical

-   Source review and traceability.
-   Exact toolkit adapter and independent contract tests.
-   ML-KEM-768 protected-read interoperability.
-   Zero-trust authorization and protected-resource behavior.
-   Key rotation/revocation state machine and node convergence.
-   Crash recovery, backup integrity and audit chain.
-   Official validator, README and evidence.

### P1 --- Core scoring and judge demonstration

-   Explainable privilege and lateral-movement detection with real
    metrics.
-   Secure messaging, replay and peer-bound resumption.
-   Full operator console and one-click scenarios.
-   Benchmark lab and requirements scorecard.

### P2 --- Polish, if time permits

-   Optional ML-DSA signed checkpoints/admin receipts after verified
    library support.
-   Optional configured OAuth for developer convenience only.
-   Additional charts, filters and nonessential visual refinements.

## 11. Acceptance gates

  ------------------------------------------------------------------------
  Gate                                Acceptance condition
  ----------------------------------- ------------------------------------
  G0 Source alignment                 Current official toolkit, adapter
                                      contract, validator, runtime and
                                      data schemas inspected; assumptions
                                      recorded.

  G1 Adapter                          All five operations pass official
                                      validator and independent tests;
                                      exact JSON/stdout behavior;
                                      persistence and no leakage.

  G2 Crypto                           Independent ML-KEM-768 decapsulation
                                      and HMAC verification pass; AEAD
                                      tamper tests pass.

  G3 Access control                   All unauthorized, revoked, expired,
                                      mismatched and unknown states deny
                                      without protected content.

  G4 Revocation                       3+ nodes; per-node enforcement and
                                      convergence measured; no old-key
                                      acceptance after cutoff.

  G5 Recovery                         Crash matrix passes;
                                      revoked/compromised keys never
                                      reactivate; invalid/stale backup
                                      rejected.

  G6 Audit                            Chain verifies normally and detects
                                      tamper, deletion, reordering, actor
                                      mutation and injection.

  G7 Detection                        Labelled evaluation produces actual
                                      metrics and explainable alert
                                      evidence.

  G8 Messaging                        Intended recipient succeeds; wrong
                                      recipient/replay/tamper/cross-peer
                                      resumption fail safely.

  G9 UI                               Main workflows use backend; no fake
                                      controls; responsive and
                                      smoke-tested.

  G10 Submission                      Clean install, pinned dependencies,
                                      README, threat model, brief, demo
                                      and evidence package complete.
  ------------------------------------------------------------------------

## 12. Risks and mitigations

  -----------------------------------------------------------------------
  Risk                                Mitigation
  ----------------------------------- -----------------------------------
  Toolkit adapter mismatch            Inspect current starter/contract
                                      first; adapter is Phase 1 and
                                      independently tested.

  PQC package API/version mismatch    Verify installed `pqcrypto==0.4.0`
                                      API and test vectors before
                                      implementation; do not guess
                                      function names or sizes.

  Scope too large                     Prioritize P0 gates; keep modular
                                      monolith; implement UI after core
                                      engine.

  Simulated behavior mistaken for     Label nodes as simulated throughout
  real distribution                   UI and documentation.

  False security claims               Maintain explicit limitations and
                                      evidence-linked scorecard.

  Detector metrics misleading         Use labelled fixtures and
                                      deterministic seeds; report
                                      unavailable metrics as not
                                      evaluated.

  State corruption or crash           Journal, transactional commit,
  inconsistency                       idempotent recovery and crash
                                      matrix.

  Secret leakage                      Structured redacted logging, safe
                                      errors, secret scans and output
                                      tests.
  -----------------------------------------------------------------------

## 13. Assumptions and open questions

-   The uploaded master build prompt is the detailed implementation
    specification, but it explicitly requires checking the latest
    official Track 4 PDF and complete toolkit before coding.
-   The exact toolkit adapter schema, validator behavior, writable state
    path and judge runtime must be confirmed from the current organizer
    toolkit.
-   The exact supported ML-KEM-768 and ML-DSA API names/parameter sets
    must be verified in the pinned library.
-   Forward secrecy remains unproven unless a vetted protocol
    implementation and exposure test are completed.
-   Any optional grace-period behavior must be made explicit and
    documented; default is zero grace for new requests after cutoff.
-   The local node cluster is a deterministic simulator, not distributed
    consensus.

## 14. Source alignment

This PRD is based on `QSHIELD_Master_Build_Prompt.pdf` (26 pages), which
identifies Q-SHIELD and its USP, lists 12 official goals, defines
toolkit operations, architecture, crypto, UI, tests, build phases,
repository structure, demo scenarios and submission evidence. The
companion `Yugaantar DevForge Tracks.pdf` identifies Track 4 as "Key
Identity Guard" and describes the sandbox prototype, sensitive workflow
protection, dynamic access changes and verifiable security telemetry.
The current toolkit and official Track 4 source remain authoritative
where they provide more specific or updated contracts.

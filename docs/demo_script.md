# Q-SHIELD — Five-Minute Demo Script

**Total Duration:** 5 minutes (300 seconds)  
**Pre-flight:** Start backend (`uvicorn backend.app.main:app --host 127.0.0.1 --port 8000`) and frontend (`npm run dev -- --host 127.0.0.1 --port 5173`). Ensure all scenarios start from **Reset Demo Data** so outcomes (`PASS`, `FAIL`, `PARTIAL`, `NOT RUN`) are deterministic and honest.

---

### 1. Product Promise & Architecture (0:00 – 0:30 | 30s)
- **Open:** Landing page (`/`) → click **Reset Demo Data** & **Issue Backend Session** on `/login` → `/overview`.
- **Action:** Point out the "Proof-Carrying Trust Changes" header, live service health, and `localStorage.length === 0`.
- **Expected Result:** Clean overview metrics loaded from SQLite via FastAPI.
- **Evaluator Observes:** Offline-first local execution, zero browser-stored secrets, clear separation of simulated nodes vs real crypto.
- **Evidence:** `reports/evidence/screenshots/01_landing.png`, `02_overview_desktop.png`.
- **Narration:** *"Q-SHIELD is a local-first quantum-ready trust and revocation control plane. Every trust change—authorization, revocation, rotation, backup, or message delivery—produces verifiable proof."*

### 2. Normal Authorized Read & Wrong-Owner Denial (0:30 – 1:10 | 40s)
- **Open:** `/scenarios` (or `/vault`).
- **Action:** Run **S01 (Normal Protected Read)** and **S02 (Wrong-Owner Denial)**.
- **Expected Result:** `S01` returns `PASS` with decrypted synthetic content for `alice`; `S02` returns `PASS` verifying `bob` is denied without plaintext leakage.
- **Evaluator Observes:** 9-step fail-closed pipeline + AES-256-GCM decryption only after authorization succeeds.
- **Evidence:** `reports/evidence/screenshots/04_scenarios_s01_pass.png`, `reports/evidence/validator_output.txt`.
- **Narration:** *"Authorized owners decrypt vault resources via AES-256-GCM; wrong-owner callers are denied at step 6 with zero plaintext or key leakage."*

### 3. Lost Device, Replacement Enrolment & Unaffected Peer (1:10 – 2:00 | 50s)
- **Open:** `/incidents` and `/devices`.
- **Action:** Trigger lost-device incident for `alice`'s device, enrol a replacement device, and verify `bob` (peer) still reads normally.
- **Expected Result:** Lost device & active sessions are revoked irreversibly, signed incident receipt is generated, and `bob` remains unaffected.
- **Evaluator Observes:** Immediate revocation + verifiable incident receipt.
- **Evidence:** `backend/tests/test_stage4_devices_sessions.py` (`4/4` PASS).
- **Narration:** *"When Alice's device is lost, revocation is irreversible and receipted, while Bob's independent peer access remains uninterrupted."*

### 4. Key Rotation, Cutoff & Node Convergence Map (2:00 – 3:00 | 60s)
- **Open:** `/keys` and `/nodes`.
- **Action:** Configure 5 **simulated** nodes, partition one node, run 4-phase key rotation, then reconcile the partitioned node.
- **Expected Result:** Old key is denied post-cutoff; partitioned node is honestly reported as non-converged until reconciliation completes.
- **Evaluator Observes:** Explicit "Simulated" node badge, honest non-convergence reporting, and 3–7 node convergence metrics.
- **Evidence:** `reports/evidence/screenshots/03_nodes.png`, `backend/tests/test_stage5_nodes_and_rotation.py`.
- **Narration:** *"Our 4-phase key rotation enforces strict cutoff across simulated nodes, honestly reporting partitioned nodes before reconciliation."*

### 5. Crash Recovery & Backup Tamper Rejection (3:00 – 3:50 | 50s)
- **Open:** `/scenarios` (crash recovery & backup scenarios) or `/keys`.
- **Action:** Run journaled rotation with simulated pre-commit crash, recover via journal, then verify & tamper-test backup manifest.
- **Expected Result:** Pre-commit crash rolls back safely without exposing unready keys; tampered backup manifest is rejected.
- **Evaluator Observes:** 7-point crash safety and HMAC-verified backup integrity.
- **Evidence:** `reports/evidence/crash_matrix.md`, `backend/tests/test_stage6_recovery_and_backups.py`.
- **Narration:** *"If power fails mid-rotation, the write-ahead journal recovers deterministically; tampered backups fail HMAC verification immediately."*

### 6. Audit Integrity & Explainable Lateral Movement Alert (3:50 – 4:40 | 50s)
- **Open:** `/audit` and `/detector`.
- **Action:** Click **Verify Chain** on `/audit`, trigger **Tamper Demo** (and observe detection), then inspect `/detector` alerts from the `22`-event practice dataset.
- **Expected Result:** Audit verifier detects hash-chain break; detector explains multi-hop lateral movement and privilege escalation rules with `0` ML dependencies.
- **Evaluator Observes:** Tamper-evident hash chain + deterministic rule explanations (`TP=5, FP=0, FN=0` on practice fixture).
- **Evidence:** `reports/detector/practice_evaluation.json`, `backend/tests/test_stage7_audit_and_receipts.py`, `test_stage8_detector.py`.
- **Narration:** *"Every event is hash-chained so tampering is caught immediately, and our zero-ML detector flags privilege escalation and lateral movement deterministically."*

### 7. Messaging Replay/Recipient-Binding & Honest Forward-Secrecy Status (4:40 – 5:20 | 40s)
- **Open:** `/messaging`.
- **Action:** Send an AEAD message, deliver it, attempt replay delivery, and inspect the Forward Secrecy status badge.
- **Expected Result:** Duplicate delivery is rejected by the durable replay ledger; Forward Secrecy badge explicitly shows **`NOT ESTABLISHED`**.
- **Evaluator Observes:** Honest security reporting without inflated claims.
- **Evidence:** `backend/tests/test_stage9_messaging.py` (`3/3` PASS).
- **Narration:** *"Messages bind recipient and sequence into AAD with a durable replay ledger, and we honestly report Forward Secrecy as NOT ESTABLISHED without an ephemeral ratchet."*

### 8. Evidence Scorecard & Measured Benchmark Summary (5:20 – 5:40 | 20s)
- **Open:** `/scorecard` and `/benchmarks`.
- **Action:** Show the live Track 4 goal-area scorecard and measured `perf_counter_ns` latencies (`35` operations, `1,475` samples).
- **Expected Result:** All measured latencies, test counts, and limitations match `reports/benchmarks/summary.md` and `docs/acceptance_gates.md`.
- **Evidence:** `reports/benchmarks/summary.md`, `reports/test_report/summary.md`.
- **Narration:** *"Everything on this scorecard traces directly to verified tests, official validator runs, and nanosecond benchmarks."*

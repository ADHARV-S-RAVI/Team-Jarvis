# Q-SHIELD — Distributed Revocation, Node Simulator & Key Rotation (Stage 5)

**Runtime:** Python `3.12.3`  
**Status:** **PASS** (`G4: PASS`; 28/28 backend tests pass)

---

## 1. Multi-Node Simulator Architecture (`backend/app/nodes/service.py`)

- **Clearly Labelled `SIMULATED`:** All nodes are local logical nodes persisted in SQLite (`simulated_nodes` and `node_acknowledgements`), not physical distributed servers or consensus clusters.
- **Configurable Node Count:** Default 3 nodes, configurable from **3 to 7** via `POST /api/v1/nodes/configure`.
- **Per-Node State:** `id`, `service_name`, `accepted_key_version`, `revoked_state_json`, `last_sequence`, `health` (`HEALTHY` / `UNREACHABLE`), `delay_ms`, `last_ack_at`, `enforced_at`, and `fault_state` (`NONE` / `PARTITIONED`).

---

## 2. Revocation Propagation & Acknowledgement Rules

1. **Central Tombstone First:** Central `RevocationTombstone` is committed before propagation begins; central policy denies immediately.
2. **Idempotent & Monotonic:** `propagate_revocation_to_nodes()` compares `epoch` against each node's stored epoch for `(subject_type, subject_id)`. Stale epochs (`epoch < existing`) are ignored (`STALE_IGNORED`); duplicate epochs return `IDEMPOTENT_ACK`.
3. **Partition Handling (`NOT_CONVERGED`):** Unreachable/partitioned nodes record `NodeAcknowledgement(result="NOT_CONVERGED")` and are never reported as converged. `node_check_access()` fails closed (`NODE_PARTITIONED_FAIL_CLOSED`) on partitioned nodes.
4. **Recovery & Reconciliation:** `POST /api/v1/nodes/{node_id}/recover` + `POST /api/v1/nodes/reconcile` monotonically replays all `RevocationTombstone` records to recovered nodes.
5. **Measured Convergence Metrics (`GET /api/v1/nodes/metrics`):** Computes actual `sample_count`, `p50_ms`, `p95_ms`, `p99_ms`, and `max_ms` from recorded `NodeAcknowledgement` rows.

---

## 3. Key Rotation State Machine & Cutoff Policy (`backend/app/keys/service.py`)

- **States:** `PREPARED -> ACTIVE -> ROTATING -> ACTIVE_NEW`; previous key transitions to `RETIRED` or `REVOKED`. `COMPROMISED` is terminal; `REVOKED` and `COMPROMISED` keys can never be reactivated.
- **4-Phase Rotation (`POST /api/v1/keys/rotate`):**
  1. `PREPARE`: Generates new `KeyMetadata` (`PREPARED`) and isolated secret KEK in `KeyMaterialStore`.
  2. `DISTRIBUTE`: Marks current key `ROTATING` and stages new version on all simulated nodes. If any node is partitioned (`NOT_CONVERGED`), aborts safely before commit and restores `current_key.state = "ACTIVE"`.
  3. `COMMIT`: Atomically promotes new key to `ACTIVE_NEW` and sets `committed=True`.
  4. `RETIRE`: Transitions previous key to `RETIRED` or `REVOKED` (with `RevocationTombstone`).
- **Cutoff & In-Flight Policy (`backend/app/policy/authz.py`):**
  - **Default zero grace period:** New requests (`in_flight=False`) using a `RETIRED` key are denied after cutoff.
  - **Explicit In-Flight Migration:** Existing vault entries encrypted under a `RETIRED` key may be decrypted only when `in_flight=True` is explicitly classified and no `REVOKED`/`COMPROMISED` state or tombstone exists.
  - New vault encryption (`store_vault_resource`) automatically uses the latest `ACTIVE` / `ACTIVE_NEW` key version.

---

## 4. Database & API Changes

- **Migration (`0004_nodes_and_key_rotation`):** Added `simulated_nodes`, `node_acknowledgements`, and `rotation_operations`.
- **New `/api/v1` Endpoints:**
  - `GET /api/v1/nodes`, `POST /api/v1/nodes/configure`, `POST /api/v1/nodes/reconcile`, `GET /api/v1/nodes/metrics`
  - `POST /api/v1/nodes/{node_id}/partition`, `POST /api/v1/nodes/{node_id}/recover`, `POST /api/v1/nodes/{node_id}/latency`
  - `POST /api/v1/keys/rotate`, `POST /api/v1/keys/{key_id}/compromise`
- **Lost-Device Integration:** `report_lost_device()` now invokes `SimulatedNodePropagationBoundary` and populates `IncidentReceipt.node_acks_json` and `convergence_ms`.

---

## 5. Known Limitations & Actual Test Results

- **Limitations:** Simulated nodes run locally in SQLite (not physical distributed servers); durable crash-recovery journal & backup integrity are deferred to Stage 6.
- **Backend Tests:** `py -3.12 -m pytest -v backend/tests/` -> **28 passed in 11.99s** (`exit=0`), including 3–7 node configuration, partition/recovery, idempotency/stale-epoch rejection, rotation abort on partition, zero-grace cutoff + `in_flight` handling, terminal `COMPROMISED`, and concurrent read-vs-revoke race test (with `_AUDIT_LOCK` serialization).
- **Alembic:** `upgrade head` -> **exit=0** (`0004_nodes_and_key_rotation`).
- **Adapter & Official Validator:** **9/9 pytest PASS** (`exit=0`), **21/21 `validate.py` checks PASS** (`exit=0`).

# Q-SHIELD — Deterministic Threat Detection & Lateral-Movement Engine (Stage 8)

**Runtime:** Python `3.12.3`  
**AI/ML Dependencies:** **None** (deterministic rules, statistics, and time-aware directed graph only)  
**Status:** **PASS** (`G7: PASS`; 42/42 backend tests pass; 1.00 F1 on `practice/events.csv`)

---

## 1. Architecture & Components (`backend/app/detector/service.py`)

1. **Schema-Flexible Parser (`normalize_event_dict`, `parse_events_csv`):** Validates core fields (`event_id`, `actor`, `action`, `event_time_utc`), preserves unknown fields in `payload_json`, and rejects malformed inputs (`400`).
2. **Clock Skew & Bounded Reordering (`ingest_detector_events`):**
   - Computes `adjusted_event_time = event_time - timedelta(milliseconds=source_clock_offset_ms)`.
   - Tracks watermark and flags `out_of_order=True` for late arrivals (within configurable `reorder_window_ms = 5000`).
   - Flags `order_uncertain=True` when adjusted timestamps for the same actor fall within `clock_uncertainty_ms = 500`.
3. **Deterministic Rule Engine & Time-Aware Graph (`run_deterministic_detection`):**
   - `RULE_PRIV_UNAPPROVED_CHANGE` & `RULE_PRIV_SELF_ESCALATION`: Flags role changes lacking a matching valid approval in `approvals` (`subject`, `role`, `valid_from_utc <= adjusted_event_time < valid_until_utc`).
   - `RULE_PRIV_SENSITIVE_AFTER_CHANGE`: Flags `allow` access in the same session following an unapproved role change.
   - `RULE_PRIV_REVOKED_ACTOR_ATTEMPT`: Flags telemetry from actors with active `RevocationTombstone` records.
   - `RULE_LATERAL_MULTI_HOP`: Builds a time-aware directed service graph per `(actor, session_id)`, excluding baseline and approved scope edges, and flags multi-hop (`>= 2`) unexpected paths while suppressing isolated single-hop denials.
   - `RULE_SERVICE_ANOMALY`: Flags high-frequency unexpected service access bursts (`>= 4`).
4. **Metrics & Synthetic Generator (`evaluate_detector_metrics`, `generate_synthetic_events`):**
   - Computes `TP`, `FP`, `TN`, `FN`, `precision`, `recall`, `f1`, `false_alerts_per_1000_benign`, `median_time_to_alert_ms`, `p95_time_to_alert_ms`, `per_rule_breakdown`, and `confusion_matrix` (or `NOT_EVALUATED` if labels are absent).
   - Seeded deterministic generator (`random.Random(seed)`).

---

## 2. Database & API Changes

- **Migration (`0006_detector_events_and_alerts`):** Added `detector_events` and `detector_alerts`.
- **New `/api/v1` Endpoints:**
  - `POST /api/v1/detector/ingest`
  - `POST /api/v1/detector/run`
  - `GET /api/v1/detector/alerts`
  - `POST /api/v1/detector/metrics`
  - `GET /api/v1/detector/rules`

---

## 3. API Key / External Provider Note
No external AI/LLM API key is used or permitted in Stage 8; Track 4 strictly prohibits AI/ML/LLM inference or model APIs in the submitted runtime.

---

## 4. Known Limitations & Practice Dataset Evaluation
- **Practice Dataset (`tools/Track-4-Toolkit/practice/`):** 22 events, `approvals.json`, `labels.csv`: `TP=5, FP=0, TN=17, FN=0, precision=1.0, recall=1.0, f1=1.0`. As noted in `practice/README.md`, these 22 examples support functional demonstration only and do not establish production false-positive rates at scale.

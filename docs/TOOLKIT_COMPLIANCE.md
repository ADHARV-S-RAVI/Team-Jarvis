# Track 4 Toolkit Compliance Matrix

**Official Toolkit:** `tools/Track-4-Toolkit/` (Track 4 Participant Toolkit v1.0.0)  
**Adapter Entry Point:** `track4_service.py`

## 1. Adapter Contract Compliance (`docs/adapter-v1.md`)

| Requirement | Official Toolkit Source | Q-SHIELD Implementation | Verification Method | Result | Remaining Gap |
|---|---|---|---|---|---|
| Single root-level adapter | `docs/adapter-v1.md` | `track4_service.py` at repository root | `validate.py --entry "../../track4_service.py"` | **PASS** | None |
| Stdin/stdout UTF-8 JSON per process | `docs/adapter-v1.md` | `track4_service.py` (`main()`) | `tests/adapter/test_track4_service.py` + `validate.py` | **PASS** | None |
| Persistent state across processes | `docs/adapter-v1.md` | Uses `TRACK4_STATE_DIR` or OS temp dir | `validate.py` cross-process revocation check | **PASS** | None |
| Diagnostics on `stderr`, zero secret leakage | `docs/adapter-v1.md` | Structured stderr only; fake key filtered | `validate.py` (`fake key stays out of output`) | **PASS** | None |
| `setup` / `read` / `revoke` / `audit` ops | `docs/adapter-v1.md` | Dispatches to Q-SHIELD policy/storage | `21/21` `validate.py` checks + `9/9` adapter pytest | **PASS** | None |
| `protected_read` ML-KEM-768 + HMAC-SHA-256 | `docs/adapter-v1.md` | `pqcrypto` ML-KEM-768 encaps + HMAC-SHA-256 over `challenge + body` | `tests/adapter/test_track4_service.py` | **PASS** | None |
| Root `threat-model.json` | `docs/adapter-v1.md` | `threat-model.json` (`protected-resource` / `identity-check`) | File inspection | **PASS** | None |
| Offline judging compatibility | `docs/adapter-v1.md` | Zero network calls; `pqcrypto==0.4.0` + Python 3.12 | Offline test execution | **PASS** | None |

## 2. Submission & Evidence Compliance (`README.md`, `templates/evidence-sheet.md`)

| Requirement | Official Toolkit Source | Q-SHIELD Location | Verification Method | Result | Remaining Gap |
|---|---|---|---|---|---|
| Toolkit kept separate from submission | `README.md` | Excluded via `.gitignore` (`tools/Track-4-Toolkit/`) | `.gitignore` inspection | **PASS** | None |
| Two-page max project brief PDF | `templates/two-page-brief.md` | `reports/submission/QSHIELD_Project_Brief.pdf` | File inspection | **PASS** | Update brief commit hash after final commit if needed |
| 12-goal traceability & evidence | `templates/evidence-sheet.md` | `docs/requirement_traceability.csv` | Cross-check against 12 goals | **PASS** | Goal 10 (Forward Secrecy) honestly marked `NOT IMPLEMENTED` |
| Threat model & 5-min demo script | `README.md` | `docs/threat_model.md`, `docs/demo_script.md` | Document inspection | **PASS** | None |

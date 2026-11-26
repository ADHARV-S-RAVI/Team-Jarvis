# Q-SHIELD — Crash Injection Matrix Report (Stage 6)

**Test Suite:** `backend/tests/test_stage6_recovery_and_backups.py`  
**Runtime:** Python `3.12.3`  
**Result:** **9/9 Stage 6 tests PASS** (all 7 crash injection points + corrupted journal + backup negative cases)

| # | Crash Injection Point | Commit Flag | Expected Recovery State | Actual Result | Evidence Reference |
|---|---|---|---|---|---|
| 1 | `after_prepare` | `False` | `RECOVERED_PRE_COMMIT`; previous key `ACTIVE`; proposed key `RETIRED` | **PASS** | `test_crash_injection_matrix_all_7_points[after_prepare-False]` |
| 2 | `after_backup` | `False` | `RECOVERED_PRE_COMMIT`; previous key `ACTIVE`; proposed key `RETIRED` | **PASS** | `test_crash_injection_matrix_all_7_points[after_backup-False]` |
| 3 | `after_node_partial_ack` | `False` | `RECOVERED_PRE_COMMIT`; previous key `ACTIVE`; proposed key `RETIRED` | **PASS** | `test_crash_injection_matrix_all_7_points[after_node_partial_ack-False]` |
| 4 | `before_commit` | `False` | `RECOVERED_PRE_COMMIT`; previous key `ACTIVE`; proposed key `RETIRED` | **PASS** | `test_crash_injection_matrix_all_7_points[before_commit-False]` |
| 5 | `immediately_after_commit` | `True` | `RECOVERED_POST_COMMIT`; new key `ACTIVE_NEW`; old key `REVOKED` | **PASS** | `test_crash_injection_matrix_all_7_points[immediately_after_commit-True]` |
| 6 | `during_retirement` | `True` | `RECOVERED_POST_COMMIT`; new key `ACTIVE_NEW`; old key `REVOKED` | **PASS** | `test_crash_injection_matrix_all_7_points[during_retirement-True]` |
| 7 | `after_revocation_tombstone` | `True` | `RECOVERED_POST_COMMIT`; new key `ACTIVE_NEW`; old key `REVOKED`; tombstone survives | **PASS** | `test_crash_injection_matrix_all_7_points[after_revocation_tombstone-True]` |

## SQLite Durability Limits
SQLite with WAL and `PRAGMA foreign_keys=ON` provides single-host ACID transaction durability, **not** distributed consensus across independent physical servers.

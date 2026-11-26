# Stage 13 — Test, Benchmark & Verification Results

**Date:** 2026-11-26  
**Status:** **PASS** (Automated verification uses synthetic P-256 WebAuthn fixtures and mocked browser camera/WebAuthn APIs; live Windows Hello hardware was not tested).

## 1. Automated Regression Results
- **Alembic Migrations (`0001`–`0009`):** `py -3.12 -m alembic -c backend/alembic.ini upgrade head` → **exit `0`**
- **Backend Suite:** `py -3.12 -m pytest -v backend/tests/` → **`52 passed, 38 warnings in 51.38s`**, **exit `0`**
  - Includes `test_stage14_security_integrity.py` covering WebAuthn registration/auth, invalid/expired/replayed challenge rejection, wrong RP/origin, corrupted signature, policy enforcement (`IDENTITY_ASSURANCE_REQUIRED`), admin recovery, device revocation invalidating bound credentials, camera demo audit metadata, HMAC manifest creation/tampering, modified/missing/unexpected file detection, baseline governance, traversal rejection, and user-selected scan metadata.
- **Official Adapter Suite:** `py -3.12 -m pytest -v tests/adapter/test_track4_service.py` → **`9 passed in 5.92s`**, **exit `0`**
- **Official Track 4 Validator:** `validate.py --entry "../../track4_service.py"` → **`Local scenario passed.` (`21/21` checks PASS)**, **exit `0`**
- **Frontend Unit Tests:** `npm run test` (`vitest run`) → **`6 passed (6)`**, **exit `0`**
- **Frontend Build:** `npm run build` (`tsc -b && vite build`) → **`built in 17.00s`**, **exit `0`**

## 2. Measured Stage 13 Benchmarks (`time.perf_counter_ns`, `reports/benchmarks/summary.md`)

| Operation | Samples | p50 (ms) | p95 (ms) | Throughput (ops/s) |
| :--- | :---: | :---: | :---: | :---: |
| `webauthn_challenge_gen` | 50 | 3.1052 | 9.2735 | 246.43 |
| `identity_freshness_check` | 50 | 0.3379 | 0.4971 | 2,843.25 |
| `integrity_sha256_1MB` | 25 | 1.9766 | 2.4298 | 502.58 |
| `integrity_sha256_10MB` | 10 | 26.1066 | 33.6166 | 37.97 |
| `integrity_manifest_verify` | 25 | 5.3464 | 9.5071 | 156.60 |
| `integrity_scan_100_files` | 5 | 160.5357 | 169.4378 | 6.33 |

# Q-SHIELD Independent Security Verification Summary

- **Generated At:** `2026-11-26T16:38:40.329930+00:00`
- **Result:** `11/12 PASS` (`1 FAIL`)

| ID | Section | Attack / Input | Expected | Observed | Status |
|---|---|---|---|---|---|
| IND-01 | Authorization & IDOR | Bob reads Alice's vault resource | HTTP 403, zero plaintext | Bob denied reading Alice's vault resource (403, zero content leakage) | **PASS** |
| IND-02 | Authorization & IDOR | Alice uses Bob's session | Policy DENY | Mismatched actor/session denied by policy engine | **PASS** |
| IND-03 | Authorization & IDOR | Alice uses Bob's device | Policy DENY | Wrong device denied by policy engine | **PASS** |
| IND-04 | Authorization & IDOR | Auditor attempts actor:revoke | Policy DENY | Auditor role denied actor:revoke | **PASS** |
| IND-05 | Authorization & IDOR | Access disabled resource | Policy DENY | Disabled resource denied | **PASS** |
| IND-06 | Authorization & IDOR | Access by disabled actor | Policy DENY | Disabled/revoked actor denied | **PASS** |
| IND-07 | Cryptographic Verification | AES-GCM tamper, wrong key, AAD mismatch, 20 nonces, HMAC | InvalidTag on tamper/mismatch; 20 unique nonces | AES-GCM tamper/wrong-key/AAD-mismatch rejected; 20/20 unique nonces; HMAC verified | **PASS** |
| IND-08 | Cryptographic Verification | ML-KEM-768 track4_service.py contract | ready=true | track4_service.py ML-KEM-768 adapter setup/contract verified | **PASS** |
| IND-09 | File Integrity Verification | Baseline init, scan, governed update, post-update scan | Persisted scans & approved baseline | {"error":"invalid_request","message":"Request validation failed","correlation_id":"ddc76226-d236-4383-9fba-48c7399ab43e"} | **FAIL** |
| IND-10 | Audit & Recovery | Modify persisted audit event reason | Hash chain verification fails | Audit chain (23 events) detected reason modification | **PASS** |
| IND-11 | Audit & Recovery | Tampered backup manifest & invalid recovery journal | Rejected with integrity error | Tampered backup manifest and corrupted recovery journal both rejected | **PASS** |
| IND-12 | Secret & Config Review | Inspect algorithms.py PRIVATE KEY string | Confirmed detection signature only | algorithms.py PEM header is a magic-byte upload detector signature, not a hardcoded secret | **PASS** |

# Q-SHIELD Automated Security Assessment Summary

- **Generated At:** `2026-11-26T16:37:22.884186+00:00`
- **Result:** `18/18 PASS` (`0 FAIL`)

| ID | Check | Category | Status | Detail |
|---|---|---|---|---|
| SEC-01 | Unauthorized Password Takeover Blocked | Authentication | **PASS** | Unauthenticated /auth/set-password rejected with HTTP 403 |
| SEC-02 | Salted Scrypt Password Auth | Authentication | **PASS** | Authorized salted scrypt password verified and session issued |
| SEC-03 | Invalid Password Rejection | Authentication | **PASS** | Invalid password rejected with HTTP 401 |
| SEC-04 | Session Revocation Enforcement | Session Security | **PASS** | Revoked session token fails validation immediately |
| SEC-05 | RBAC Least-Privilege Deny | Authorization | **PASS** | Auditor denied actor:revoke (fail-closed RBAC) |
| SEC-06 | Fail-Closed Unknown Action | Authorization | **PASS** | Unknown action denied by default |
| SEC-07 | Device Revocation Enforcement | Trust Plane | **PASS** | Revoked device denied access (fail-closed) |
| SEC-08 | Key Generation & Rotation | Cryptography | **PASS** | Rotated key to v3 |
| SEC-09 | Crash-Safe Journaled Recovery | Resilience | **PASS** | Recovered crashed journaled rotation d75caf9b-b732-486c-bbf6-d6f474f9a54f |
| SEC-10 | Key Compromise Quarantine | Cryptography | **PASS** | Key key-v5 marked COMPROMISED and new active key rotated |
| SEC-11 | AES-256-GCM Vault Confidentiality | Cryptography | **PASS** | AES-256-GCM vault round-trip verified |
| SEC-12 | Messaging Replay Protection | Protocol Security | **PASS** | Duplicate message delivery/replay rejected |
| SEC-13 | Audit Hash-Chain & Tamper Detection | Auditability | **PASS** | Audit chain valid (39 events) and tamper detection verified |
| SEC-14 | Deterministic Rule Detector | Detection | **PASS** | Deterministic detector ran cleanly (alerts=0) |
| SEC-15 | WebAuthn Challenge Replay Guard | Identity Assurance | **PASS** | Single-use WebAuthn challenge replay blocked |
| SEC-16 | System File Integrity Monitoring | Integrity | **PASS** | FIM baseline & scan executed (status=OK) |
| SEC-17 | Backup Manifest Digest Verification | Integrity | **PASS** | Backup manifest valid; tampered digest rejected |
| SEC-18 | Simulated Node Partition Recovery | Sandbox Simulation | **PASS** | Simulated node partition recovery and reconciliation verified |

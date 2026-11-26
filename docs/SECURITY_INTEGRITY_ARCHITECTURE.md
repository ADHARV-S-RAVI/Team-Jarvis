# Stage 13 — Security Integrity Architecture

```text
[Browser UI: /security-integrity]
  |-- WebAuthn (navigator.credentials) ----------> [/api/v1/identity-assurance/* (webauthn 3.0.1)]
  |-- Explicit Camera Demo (MediaStream local) --> [Audit Metadata Only (STARTED/STOPPED)]
  |-- Scope B Client SHA-256 Metadata -----------> [/api/v1/integrity/scans/user-selected]
  |-- Scope A App Integrity Controls ------------> [/api/v1/integrity/* (Streaming SHA-256 + HMAC)]
                                                          |
  +-------------------------------------------------------+
  | Shared Enforcement, Detection & Ledger                v
  |-- Policy Step 9 Assurance Freshness Check (backend/app/policy/authz.py)
  |-- Device Revocation -> Credential Revocation (backend/app/devices/service.py)
  |-- 8 Deterministic Stage 13 Rules (backend/app/detector/service.py)
  |-- Incidents & Append-Only Audit Ledger
```

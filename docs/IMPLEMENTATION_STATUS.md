# Q-SHIELD — Implementation Status

| Capability | Status | Evidence / Notes |
|---|---|---|
| User registration (`User` role only, `scrypt`) | **IMPLEMENTED** | `POST /api/v1/auth/register`, `verify_auth_playwright.py` |
| Role-based login (`User`, `Employee`, `Admin`) | **IMPLEMENTED** | `POST /api/v1/auth/role-login`, `test_rbac_auth_workflow.py` |
| Backend-enforced RBAC & protected files | **IMPLEMENTED** | `rbac_auth_router.py`, `/api/v1/files/*`, `/api/v1/admin/*` |
| `HttpOnly` cookie sessions & 256-bit secret hashes | **IMPLEMENTED** | `sessions.session_secret_hash`, `GET /api/v1/auth/session-status` |
| Session expiration, revocation & logout | **IMPLEMENTED** | `POST /api/v1/auth/logout`, `test_rbac_auth_workflow.py` |
| WebAuthn / Passkey backend & UI | **IMPLEMENTED** | `SettingsPage.tsx`, `AuthPortalPage.tsx`, `/auth/passkey-login/*` |
| Synthetic WebAuthn registration & login tests | **IMPLEMENTED** | `test_stage14_security_integrity.py`, `test_rbac_auth_workflow.py` |
| Real Windows Hello hardware verification | **NOT VERIFIED** | Requires physical Windows Hello device outside headless CI |
| Camera preview (explicit consent, `Stop Camera`) | **IMPLEMENTED** | `AuthPortalPage.tsx`, `CameraDemoPreview.tsx` |
| Facial biometric matching | **NOT IMPLEMENTED** | Disclosed across UI, API, and README |
| Multi-node revocation convergence (`sim-node-1..7`) | **SIMULATED** | In-process SQLite logical nodes |
| Forward secrecy / ML-DSA signatures | **NOT IMPLEMENTED** | Disclosed as `NOT_ESTABLISHED` / `NOT IMPLEMENTED` |

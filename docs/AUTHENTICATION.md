# Q-SHIELD — Authentication & Identity Verification

## 1. Distinction Between Mechanisms
- **Password Authentication (`scrypt`):** Mandatory primary credential verification (`POST /api/v1/auth/role-login`) using `hashlib.scrypt` with a 16-byte random salt per password and constant-time `hmac.compare_digest`.
- **WebAuthn / Passkey Authentication (`webauthn==3.0.1`):** Cryptographic public-key challenge-response (`POST /api/v1/identity-assurance/register/*`, `POST /api/v1/auth/passkey-login/*`). Validates challenge, single-use replay, expiration, origin, RP ID, signature, and credential ownership.
- **Windows Hello Local Verification:** On Windows devices, `navigator.credentials.create()` / `get()` delegates local biometric/PIN verification to Windows Hello. Q-SHIELD never receives or stores facial templates, fingerprints, or PINs.
- **Camera Preview:** Explicit-consent `getUserMedia` visual preview with `CAMERA ACTIVE` indicator and `Stop Camera` cleanup. Does not upload frames or perform biometric matching.
- **Facial Biometric Recognition:** **NOT IMPLEMENTED.**

## 2. Session & Cookie Lifecycle
- Login and registration generate a fresh `AuthSession` ID and a 256-bit `secrets.token_bytes(32)` session secret (stored only as `SHA-256` in `sessions.session_secret_hash`).
- `HttpOnly`, `SameSite=lax` cookies (`qshield_session_id`, `qshield_session_token`) persist sessions across page refreshes and tabs (`GET /api/v1/auth/session-status`).
- `POST /api/v1/auth/logout` revokes the session, clears `session_secret_hash`, deletes cookies, clears React Query cache, and stops any active camera tracks.

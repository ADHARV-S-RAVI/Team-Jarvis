# Stage 13 — Identity Assurance Center

## 1. Overview
Q-SHIELD Stage 13 introduces post-login cryptographic Identity Assurance via WebAuthn / FIDO2 (`webauthn==3.0.1`), configurable freshness policies, device-revocation binding, audit logging, and deterministic detection rules (`backend/app/identity_assurance/service.py`).

## 2. Verification Flow & Policies
1. Actor authenticates via `/api/v1/auth/demo-login`.
2. Backend exposes `/api/v1/identity-assurance/status` showing current `assurance_level` (`STANDARD_SESSION` or `WEBAUTHN_ELEVATED`), `fresh_verified`, `fresh_until`, and configured policy.
3. Configurable policy (`AssurancePolicyConfig`, modifiable by `Security Operator` / `Admin` only):
   - `OPTIONAL`
   - `REQUIRED_FOR_SENSITIVE_ACTIONS` (`resource:read`, `resource:write`, `resource:delete`, `key:rotate`, `device:replace`)
   - `REQUIRED_AFTER_LOGIN`
4. Configurable freshness window (`freshness_window_seconds`, default `300s`). Expired assurance is never silently extended.
5. `evaluate_authorization` Step 9 fails closed with `IDENTITY_ASSURANCE_REQUIRED` when elevated assurance is required and expired/absent.

## 3. Security Controls & Device Binding
- Single-use 32-byte CSPRNG challenges (`120s` TTL, bound to `actor_id` and `purpose`).
- Sliding-window rate limiting (`5` failures / `60s`) + automatic `IDENTITY_REPEATED_FAILURE` Incident after 3+ failures.
- Bound `Device` revocation immediately revokes associated `IdentityCredential` rows and blocks authentication (`REVOKED_REJECTED`).
- Admin recovery (`/api/v1/identity-assurance/recovery`) requires operator authority and emits an audited `RECOVERY_ADMIN` event.

# Q-SHIELD — Security Architecture

## 1. Defense-in-Depth Layers
1. **Authentication Layer:** Salted `scrypt` passwords, temporary account lockout (`locked_until` after 5 failed attempts), WebAuthn passkeys, and `HttpOnly` cookie sessions with 256-bit server-side session secret hashes.
2. **Backend RBAC & 9-Step Policy Gate:** `require_any_role` and `require_admin_role` (`backend/app/api/v1/rbac_auth_router.py`) enforce `User`, `Employee`, and `Admin` boundaries on every protected endpoint and file download, paired with the 9-step fail-closed `authz.py` pipeline.
3. **Cryptographic Layer:** AES-256-GCM AEAD with AAD binding (`vault/service.py`, `messaging/service.py`) and `pqcrypto` ML-KEM-768 adapter interoperability (`track4_service.py`).
4. **Integrity & Audit Layer:** Append-only SHA-256 hash-chained `audit_events`, 7-point crash-safe rotation journals, HMAC-verified backup manifests, and SHA-256 File Integrity Monitoring (`integrity/service.py`).
5. **Deterministic Detection:** Rule-based lateral-movement detector (`detector/service.py`) with zero AI/ML runtime dependencies.

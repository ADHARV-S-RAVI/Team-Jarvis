# Q-SHIELD — Threat Model

## Part 1: One-Page Threat Model Summary

| Dimension | Summary |
| :--- | :--- |
| **Protected Assets** | Vault resource plaintext/DEKs, `master_kek.key`, identity/device/session state, key rotation journals, hash-chained audit ledger, backup manifests, and secure message payloads. |
| **Adversaries** | (1) Unauthenticated/wrong-owner caller; (2) Stolen/lost enrolled device with valid prior session; (3) Insider/operator attempting unauthorized tampering or unapproved privilege escalation; (4) Network/replay attacker reordering, dropping, or replaying messages. |
| **Trust Boundaries** | Client/UI ↔ FastAPI API (`localhost:5173`→`8000`); Toolkit CLI ↔ `track4_service.py`; FastAPI ↔ SQLite + `.qshield_keys/`; Control Plane ↔ Simulated Nodes (`sim-node-1..7`). |
| **Core Defenses** | 9-step fail-closed authz; irreversible device/session revocation; 4-phase key rotation with cutoff; 7-point crash journal recovery; HMAC-signed backups; hash-chained audit ledger; deterministic lateral-movement detector; AEAD + durable replay ledger. |
| **Residual Risks** | Local filesystem key storage (no HSM); simulated rather than physical distributed nodes; forward secrecy `NOT_ESTABLISHED`; `ML-DSA` not implemented; synthetic/practice detector dataset only. |

---

## Part 2: Detailed Threat Model

### 1. Assets & Security Properties
- **Vault Resources (`vault_entries`):** Confidentiality and integrity (AES-256-GCM + AAD).
- **Master KEK & Key Versions (`.qshield_keys/`):** Confidentiality and lifecycle integrity (revoked/retired keys denied post-cutoff).
- **Sessions & Devices:** Authentication and non-reuse after revocation/logout/expiry.
- **Audit Ledger (`audit_events`):** Tamper-evidence via `prev_hash` + `entry_hash` + HMAC-SHA-256.

### 2. Attack Surfaces & Mitigations
- **Stolen Device / Active Session:** Mitigated by immediate lost-device incident workflow (`/api/v1/incidents/lost-device`), revoking device & sessions, issuing incident receipt, and preserving unaffected peer access (`bob`).
- **Stale Key Reuse After Rotation:** Mitigated by 4-phase rotation cutoff and 9-step pipeline step 8 (`key_version` revocation check).
- **Crash Mid-Rotation:** Mitigated by write-ahead `rotation_journal` recovering cleanly across all 7 crash points (`after_prepare` through `after_revocation_tombstone`).
- **Audit Tampering / Secret Leakage:** Mitigated by `POST /api/v1/audit/verify` detecting row modification, deletion, and chain breaks, plus automatic redaction of tokens/keys/plaintext.
- **Message Replay & Cross-Peer Misdelivery:** Mitigated by recipient-bound AAD, durable `replay_records`, and peer-bound `session_resumption_tokens`.

### 3. Assumptions & Out-of-Scope Threats
- Assumes host OS filesystem permissions protect `.qshield_keys/` and SQLite DB.
- Physical side-channel attacks, compromised host kernel, and multi-host Byzantine network consensus are out of scope for this local prototype.

# Q-SHIELD — Cryptographic Design

## 1. Vetted Primitives Only (`backend/app/crypto/provider.py`)
Q-SHIELD implements zero custom cryptographic algorithms. All operations delegate to:
- **ML-KEM-768** (`pqcrypto 0.4.0` — `pqcrypto.kem.ml_kem_768`): Post-quantum key encapsulation for `protected_read` and key transport interop.
- **AES-256-GCM** (`cryptography 50.0.2` — `AESGCM`): Authenticated encryption with 12-byte random CSPRNG nonces (`os.urandom(12)`) and 16-byte authentication tags.
- **HKDF-SHA-256** (`cryptography 50.0.2` — `HKDF`): Key derivation verified against RFC 5869 test vectors.
- **HMAC-SHA-256 & SHA-256** (`hashlib`, `hmac`): Audit chain integrity and backup manifest signatures, verified against RFC 4231 test vectors.
- **ML-DSA:** **NOT IMPLEMENTED.**

## 2. Key Lifecycle & Protected Vault
- A local Master Key-Encryption Key (`master_kek.key`) wraps per-resource Data-Encryption Keys (DEKs).
- Key version metadata (`key_versions.json` + SQLite `key_versions` table) is separated from secret key bytes.
- Vault resources (`vault_entries`) store only ciphertext, nonce, tag, key version ID, and AAD; plaintext is never persisted to SQLite or logs.
- 4-phase key rotation (`PREPARE` → `BACKUP` → `PROPAGATE` → `COMMIT/RETIRE`) enforces strict post-cutoff denial of retired/compromised keys.

## 3. Secure Messaging, Replay Protection & Forward Secrecy
- Messages are encrypted with AES-256-GCM using AAD bound to `sender_id`, `recipient_id`, `session_id`, `sequence_no`, and `message_id`.
- Wrong-recipient decryption or modified AAD fails authentication (`CryptoError` / HTTP 403/400).
- A durable SQLite replay ledger (`replay_records`) rejects duplicate `message_id` or non-monotonic sequence numbers.
- **Forward Secrecy Status:** Explicitly reported as **`NOT_ESTABLISHED`** (`GET /api/v1/messages/security-status`) because Q-SHIELD uses session/KEK-derived symmetric keys without a per-message ephemeral DH/KEM ratchet.

## 4. Key Storage Limitations
- Keys reside on the local filesystem (`.qshield_keys/` or `QSHIELD_KEY_STORE_DIR`) rather than a hardware HSM or OS-enclave KMS.

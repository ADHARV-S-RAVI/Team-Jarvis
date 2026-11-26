# Q-SHIELD — Cryptographic Provider & Protected Vault (Stage 3)

**Runtime:** Python `3.12.3`  
**Libraries:** `pqcrypto==0.4.0`, `cryptography==50.0.2`, Python stdlib `hashlib` / `hmac` / `os.urandom`  
**Status:** **PASS** (`G2: PASS`; 21/21 backend & crypto tests pass)

---

## 1. Cryptographic Provider (`backend/app/crypto/provider.py`)

All cryptographic operations are routed through vetted library APIs with explicit algorithm identifiers (`CRYPTO_PROVIDER_VERSION = "1.0"`):

| Algorithm | Library / API | Parameters | Purpose |
| :--- | :--- | :--- | :--- |
| `ML-KEM-768` | `pqcrypto.kem.ml_kem_768` | PK `1184 B`, SK `2400 B`, CT `1088 B`, SS `32 B` | PQC key encapsulation & decapsulation |
| `AES-256-GCM` | `cryptography.hazmat.primitives.ciphers.aead.AESGCM` | `32 B` key, `12 B` OS CSPRNG nonce, `16 B` tag | Authenticated encryption of vault payloads & DEK wrapping |
| `HKDF-SHA-256` | `cryptography.hazmat.primitives.kdf.hkdf.HKDF` | `SHA-256`, purpose-separated `info` labels | Key derivation (`qshield:<purpose>:v<N>`) |
| `HMAC-SHA-256` | `hmac.new(..., hashlib.sha256)` + `hmac.compare_digest` | Lowercase hex digest | Integrity verification / constant-time MAC check |
| `SHA-256` | `hashlib.sha256` | `32 B` digest | Hashing & audit metadata |
| `OS CSPRNG` | `os.urandom` | OS entropy source | Nonces, random DEKs, KEKs |

- **Startup Self-Test (`run_crypto_self_test`):** Runs on `create_app()` startup, verifying RFC 5869 Appendix A.1 HKDF-SHA-256 Test Case 1, AES-256-GCM roundtrip + AAD tamper rejection, and ML-KEM-768 encapsulation/decapsulation roundtrip.

---

## 2. Key Management Foundation (`backend/app/keys/service.py`)

- **Metadata vs. Secret Separation:** `KeyMetadata` (`id`, `version`, `algorithm`, `state`, timestamps) lives in SQLite `key_metadata`; secret KEK material lives in `KeyMaterialStore` (`.qshield_keys/key_versions.json` wrapped with a 256-bit master key from `QSHIELD_MASTER_KEY_B64` or `.qshield_keys/master_kek.key` with `0600` permissions).
- **Envelope Encryption:** Each vault resource uses a fresh random 256-bit DEK (`os.urandom(32)`), wrapped with an HKDF-SHA-256 purpose-separated key derived from the active `key_version`.
- **No Secret Exposure:** Key endpoints (`GET /api/v1/keys`, `POST /api/v1/keys/generate`) return metadata only; raw keys and DEKs are never returned or logged.

---

## 3. Protected Vault (`backend/app/vault/service.py` & `vault_entries`)

- **Storage (`0002_vault_entries`):** `vault_entries` stores `resource_id`, `schema_version`, `algorithm`, `key_version`, `nonce_b64`, `ciphertext_b64`, `tag_b64`, `wrapped_dek_b64`, `wrapped_dek_nonce_b64`, `wrapped_dek_tag_b64`, and `aad_b64`. Plaintext is **never** persisted.
- **AAD Binding:** Canonical JSON of `(schema_version, resource_id, owner_actor_id, key_version, algorithm)`.
- **Zero-Trust Read Path (`POST /api/v1/vault/resources/{resource_id}/read`):**
  1. Executes the 9-step `evaluate_authorization()` pipeline FIRST.
  2. Records an `AuditEvent` (`ALLOW` or `DENY`).
  3. Immediately returns `403 Forbidden` on any denial without touching `VaultEntry` or decrypting.
  4. Only on `ALLOW`, unwraps the DEK, verifies AES-256-GCM tag and AAD, and returns plaintext.

---

## 4. Local Development Threat Model & Limitations

1. **Not an HSM:** `KeyMaterialStore` protects KEKs on the local filesystem using OS file permissions and a local master key (or `QSHIELD_MASTER_KEY_B64`). A compromised host OS or root attacker with disk/memory access is outside the local threat boundary.
2. **Forward Secrecy:** Not claimed or established by ML-KEM-768 or static envelope encryption alone.
3. **ML-DSA:** Not implemented in Stage 3 (deferred per Stage 3 rules).
4. **Full Key Rotation:** Deferred to Stage 5; Stage 3 provides versioned key generation and metadata separation only.

---

## 5. Actual Verification Results (Python `3.12.3`)

- `py -3.12 -m pytest -v backend/tests/`: **21 passed in 5.39s** (`exit=0`), including RFC 5869 HKDF KAT, RFC 4231 HMAC KAT, ML-KEM-768 roundtrip/wrong-key, AES-256-GCM nonce uniqueness & ciphertext/tag/AAD tamper rejection, raw SQLite plaintext-absence check, and unauthorized/revoked vault access denials.
- `py -3.12 -m alembic -c backend/alembic.ini upgrade head`: **exit=0** (`0002_vault_entries`).
- `py -3.12 -m pytest -v tests/adapter/test_track4_service.py`: **9 passed in 4.61s** (`exit=0`).
- `py -3.12 validate.py --entry "../../track4_service.py"`: **Local scenario passed** (**21/21 checks PASS**, `exit=0`).

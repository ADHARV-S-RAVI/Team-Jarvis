# Stage 13 — WebAuthn & Passkey Implementation

## 1. Library & Protocol
- Server verification delegates exclusively to Duo Labs' **`webauthn==3.0.1`** (`cbor2==6.3.0`, `cryptography==50.0.2`). No custom signature or CBOR verification is implemented.
- Supports ES256 (`-7`), EdDSA (`-8`), and RS256 (`-257`).

## 2. Biometrics & Key Storage Boundaries
- When using Windows Hello (facial recognition, fingerprint, PIN) or any OS platform authenticator, **the OS performs biometric verification locally**.
- Q-SHIELD **never** receives, extracts, transmits, or stores facial images, biometric templates, or WebAuthn private keys.
- Only COSE public-key bytes (`public_key_b64`), credential ID, sign counter, and non-biometric metadata are stored in SQLite (`identity_credentials`).

## 3. Localhost Development Exception
- WebAuthn normally requires HTTPS origins; browsers allow `http://localhost:5173` and `http://127.0.0.1:5173` as secure contexts for local development. RP IDs and origins are validated server-side against `ALLOWED_RP_IDS` and `ALLOWED_ORIGINS`.

## 4. Testing Honesty
- Automated verification in `backend/tests/test_stage14_security_integrity.py` exercises real server-side CBOR & ECDSA P-256 verification using a **synthetic P-256 WebAuthn test fixture**, not live Windows Hello hardware.

# Stage 13 — Known Limitations

1. **WebAuthn Testing Scope:** Automated backend tests validate real CBOR/P-256 assertions using synthetic test fixtures, and frontend tests mock `navigator.mediaDevices` / WebAuthn. Live Windows Hello hardware biometrics were not invoked during automated CI runs.
2. **Local Host Trust Anchor:** HMAC manifest protection relies on `.qshield_keys/master_kek.key` on the local host; a compromised host administrator could modify both local code and local key storage without an external signed manifest / HSM.
3. **Browser Scan Scope:** Scope B (`USER_SELECTED_METADATA`) can only hash files explicitly chosen by the user; full endpoint filesystem scanning is future desktop-agent scope.
4. **Camera Demo Non-Authenticating:** The Live Camera Demo is strictly visual; it never identifies the account holder, takes snapshots, or uploads images.
5. **Malware Scanning:** Integrity checks detect file drift/tampering against a baseline and do **not** constitute antivirus/malware signature scanning.

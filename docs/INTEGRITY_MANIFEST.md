# Stage 13 — Integrity Manifest & Governance

## 1. Protected Baseline Storage
- Active baselines (`IntegrityManifest` + `IntegrityManifestEntry`) are initialized explicitly by an authorized `Security Operator` / `Admin` (`POST /api/v1/integrity/baseline/initialize`).
- Canonical entries (`sorted([relative_path, sha256_hash, file_size])`) produce a SHA-256 `root_hash`.
- Integrity is protected by `manifest_hmac` derived via `HKDF-SHA-256` from Q-SHIELD's local master KEK (`.qshield_keys/master_kek.key`) — separated from scanned files and containing zero file contents or secrets.

## 2. Tamper Detection & Governance
- `verify_manifest_integrity` recomputes both `root_hash` and `manifest_hmac`. Any mismatch flips manifest `status="TAMPERED"`, creates a `CRITICAL` `INTEGRITY_BASELINE_TAMPER` Incident, triggers `RULE_INTEGRITY_BASELINE_TAMPER`, and fails scans closed.
- Detected file modifications (`MODIFIED` / `MISSING`) are **never** auto-approved. Operators submit a `BaselineChangeRequest` (`POST /api/v1/integrity/baseline/change-requests`), which requires authorized operator approval/rejection with audit correlation.
- **Limitation:** Against a compromised local host administrator with root filesystem access to `.qshield_keys/`, local trust anchors cannot prevent host-level forgery without an external signed trust anchor/HSM.

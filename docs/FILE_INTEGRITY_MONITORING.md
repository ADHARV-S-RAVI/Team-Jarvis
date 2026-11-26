# Stage 13 — File Integrity Intelligence Monitoring

## 1. Three Scanning Scopes (Truthful Boundaries)
- **Scope A (`APPLICATION_FILES`) — Implemented:** Backend scanner (`backend/app/integrity/service.py`) walks permitted Q-SHIELD application paths (`backend/app/`, `track4_service.py`, `frontend/src/`), hashing files with `1 MiB` streaming SHA-256.
- **Scope B (`USER_SELECTED_METADATA`) — Implemented:** Users explicitly pick files in the browser via `<input type="file">`. Files are hashed **locally in-browser** using WebCrypto `crypto.subtle.digest("SHA-256")` and only metadata/hashes are sent to `/api/v1/integrity/scans/user-selected` (zero file contents uploaded).
- **Scope C (Full Endpoint Agent) — Future Scope:** Websites cannot and must not silently enumerate a user's OS filesystem. Full endpoint monitoring requires a future native desktop agent.

## 2. Exclusions & Protections
- Strictly excludes `__pycache__`, `node_modules`, `.git`, `.qshield_keys`, `.qshield_uploads`, `.pytest_cache`, `dist`, and `.db`/`.key`/`.pyc` files.
- Enforces `100 MiB` per-file limit, duration limits, cancellation (`/scans/{id}/cancel`), path-traversal rejection (`..`), and symlink containment checks (`followlinks=False`).

## 3. Integrity Statuses
`VERIFIED`, `MODIFIED`, `MISSING`, `UNEXPECTED`, `UNREADABLE`, `EXCLUDED`, `NOT_SCANNED`, `BASELINE_UNAVAILABLE`.

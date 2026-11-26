# Q-SHIELD — Official Toolkit Gap Analysis

**Official Toolkit Repository:** `https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit`  
**Local Clone Path:** `tools/Track-4-Toolkit/`  
**Commit Hash:** `8901dfbdbfe048853e0bfa25b60583d1e6617a63` (`v1.0.0`)  
**Authoritative Spec:** `tools/Track-4-Toolkit/docs/adapter-v1.md`, `tools/Track-4-Toolkit/validate.py`, `tools/Track-4-Toolkit/starters/python/track4_service.py`

---

## 1. Contract Comparison Table

| # | Official Requirement (`adapter-v1.md` / `validate.py`) | Stage 1 Initial Implementation | Match Status | Required Correction | Verification Method |
|---|---|---|---|---|---|
| 1 | **`setup` field `disabled`:** `disabled` lists actor IDs to disable at setup (`{"op":"setup","owners":...,"contents":...,"disabled":[...],"key_material":...}`). | Read `request.get("disabled_actors", [])` instead of `disabled`. | **MISMATCH** | Read `request.get("disabled", request.get("disabled_actors", []))` and validate as `list[str]`. | `validate.py` + `pytest` |
| 2 | **`protected_read` response field `proof`:** Return KEM ciphertext as Base64 in `ciphertext` and lowercase-hex HMAC-SHA-256 in `proof`. | Returned `"hmac"` instead of `"proof"`. | **MISMATCH** | Return `"proof": mac_hex` (and remove non-standard `"hmac"` key). | `pytest` ML-KEM-768 interop test |
| 3 | **`protected_read` HMAC input:** Keyed by ML-KEM-768 shared secret over `UTF8(challenge + stored_body)` with no separator. | `hmac.new(shared_secret, (challenge + stored_body).encode("utf-8"), hashlib.sha256).hexdigest()`. | **MATCH** | None. | `pytest` independent decapsulation |
| 4 | **`protected_read` ML-KEM-768:** Standard Base64 raw ML-KEM-768 public key; vetted `pqcrypto==0.4.0`. | Used `pqcrypto.kem.ml_kem_768.encrypt` with `base64.b64decode(..., validate=True)` and `len == 1184`. | **MATCH** | None. | `pytest` + package inspection |
| 5 | **`read` operation:** `actor`, `asset`, `request_id`; allow returns `{"decision":"allow","body":"<exact>"}`; deny returns `{"decision":"deny"}` with no content/snippet. | Returned `{"decision":"allow","request_id":...,"asset":...,"body":...}` and `{"decision":"deny"}`. | **MATCH** | Keep exact `decision` and `body`; record `request_id` decision before returning. | `validate.py` + `pytest` |
| 6 | **`revoke` operation:** `actor`; persist revocation; return a JSON object (e.g., `{}`). Other actors retain access. | Persists actor in `revoked_actors` atomically; returns `{"status":"revoked","actor":...,"revoked":true}`. | **MATCH** | None. | `validate.py` + `pytest` |
| 7 | **`audit` operation:** `request_id`; return recorded `request_id` and `decision` (`"allow"` or `"deny"`). | Returns `{"found":True,"request_id":...,"decision":...,"actor":...,"op":...}` for recorded reads. | **MATCH** | Ensure unknown `request_id` returns `{"found":False,"request_id":...,"error":"unknown_request"}` without violating `validate.py`. | `validate.py` + `pytest` |
| 8 | **Process & I/O contract:** New process per request; 1 UTF-8 JSON on `stdin` to EOF; 1 JSON on `stdout`; diagnostics on `stderr`; `allow_nan=False`. | Reads `sys.stdin.read()`, writes 1 JSON line to `stdout`, diagnostics to `stderr`. | **MATCH** | Add `allow_nan=False` to `json.dumps` to match official starter. | `validate.py` + `pytest` |
| 9 | **State persistence & temp dir:** Use `TRACK4_STATE_DIR` if set, else OS temp dir. Persist before acknowledging. | Used `TRACK4_STATE_DIR` with fallback to `tempfile.gettempdir() / "qshield_track4_state"`, atomic `mkstemp` + `fsync` + `os.replace`. | **MATCH** | None. | `validate.py` + `pytest` |
| 10 | **Secret/content non-disclosure:** Keep `key_material`, shared secrets, and protected content out of `stdout` (on deny/error) and `stderr`. | Sanitized `stderr` logging; `key_material` stored only, never logged; `del shared_secret`. | **MATCH** | None. | `validate.py` (`fake key stays out of output`) + `pytest` |
| 11 | **Judging runtime:** Python 3.12 with `pqcrypto==0.4.0`. | Stage 1 initially ran on Python `3.11.9`. | **GAP** | Verify Python `3.12.3` runtime with `pqcrypto==0.4.0` and run `validate.py` + `pytest` under Python `3.12.3`. | `py -3.12 validate.py` & `py -3.12 -m pytest` |

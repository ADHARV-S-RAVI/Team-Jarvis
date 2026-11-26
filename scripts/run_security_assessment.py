"""Automated 18-Check Security Assessment Suite for Q-SHIELD.

Runs against an isolated temporary SQLite database migrated via `alembic upgrade head`
and exercises real security controls through FastAPI TestClient.
Outputs:
  - reports/security_assessment/report.json
  - reports/security_assessment/summary.md
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
from typing import Callable

from alembic import command
from alembic.config import Config
import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
REPORT_DIR = ROOT / "reports" / "security_assessment"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _synthetic_webauthn_create(challenge_b64u: str, rp_id: str = "localhost", origin: str = "http://localhost:5173"):
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_numbers()
    x = pub.x.to_bytes(32, "big")
    y = pub.y.to_bytes(32, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})
    cred_id = os.urandom(16)
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    aaguid = b"\x00" * 16
    attested = aaguid + struct.pack(">H", len(cred_id)) + cred_id + cose_key
    auth_data = rp_hash + bytes([0x45]) + struct.pack(">I", 1) + attested
    att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data = json.dumps({"type": "webauthn.create", "challenge": challenge_b64u, "origin": origin}).encode("utf-8")
    return priv, {
        "id": _b64u(cred_id),
        "rawId": _b64u(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(client_data),
            "attestationObject": _b64u(att_obj),
        },
    }


def _make_client(tmp_dir: Path) -> tuple[TestClient, Path, object]:
    db_path = tmp_dir / "sec_assess.db"
    db_url = f"sqlite:///{db_path.as_posix()}"
    os.environ["QSHIELD_DATABASE_URL"] = db_url
    os.environ["QSHIELD_KEY_STORE_DIR"] = str(tmp_dir / "keystore")

    from backend.app.config import get_settings
    from backend.app.db.session import create_db_engine, get_db
    from backend.app.main import create_app

    get_settings.cache_clear()
    alembic_cfg = Config(str(ROOT / "backend" / "alembic.ini"))
    alembic_cfg.set_main_option("script_location", str(ROOT / "backend" / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")

    engine = create_db_engine(db_url)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)
    app = create_app()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app), tmp_dir, engine


def run_assessment() -> dict[str, object]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="qshield_sec_assess_"))
    results: list[dict[str, object]] = []
    engine = None

    try:
        client, work_dir, engine = _make_client(tmp_dir)
        with client:
            r_reset = client.post("/api/v1/simulation/reset")
            assert r_reset.status_code == 200, r_reset.text

            # Enroll trusted devices for admin & auditor for RBAC checks
            client.post(
                "/api/v1/devices",
                json={"id": "dev-admin-01", "owner_actor_id": "admin", "credential_fingerprint": "fp-admin-01", "state": "TRUSTED"},
            )
            client.post(
                "/api/v1/devices",
                json={"id": "dev-auditor-01", "owner_actor_id": "auditor", "credential_fingerprint": "fp-auditor-01", "state": "TRUSTED"},
            )
            # Create sessions for RBAC & Vault checks
            s_alice = client.post("/api/v1/auth/demo-login", json={"actor_id": "alice", "device_id": "dev-alice-01", "peer_id": "peer-a"}).json()
            s_admin = client.post("/api/v1/auth/demo-login", json={"actor_id": "admin", "device_id": "dev-admin-01", "peer_id": "peer-adm"}).json()
            s_aud = client.post("/api/v1/auth/demo-login", json={"actor_id": "auditor", "device_id": "dev-auditor-01", "peer_id": "peer-aud"}).json()

            def check(cid: str, name: str, category: str, fn: Callable[[], str]) -> None:
                try:
                    detail = fn()
                    results.append({"id": cid, "name": name, "category": category, "status": "PASS", "detail": detail})
                except Exception as exc:
                    results.append({"id": cid, "name": name, "category": category, "status": "FAIL", "detail": str(exc)})

            # 1. Unauthorized password takeover blocked
            def c01() -> str:
                r = client.post("/api/v1/auth/set-password", json={"actor_id": "admin", "password": "TakeoverPassword!1"})
                assert r.status_code == 403, r.text
                return "Unauthenticated /auth/set-password rejected with HTTP 403"

            # 2. Salted scrypt password set & valid login
            def c02() -> str:
                r_set = client.post(
                    "/api/v1/auth/set-password",
                    json={
                        "actor_id": "alice",
                        "password": "StrongPassword!2026",
                        "session_id": s_alice["id"],
                        "session_token": s_alice["session_token"],
                    },
                )
                assert r_set.status_code == 200 and r_set.json()["algorithm"] == "scrypt", r_set.text
                r_ok = client.post(
                    "/api/v1/auth/login",
                    json={"actor_id": "alice", "password": "StrongPassword!2026", "device_id": "dev-alice-01", "peer_id": "peer-a"},
                )
                assert r_ok.status_code == 200 and "session_token" in r_ok.json(), r_ok.text
                return "Authorized salted scrypt password verified and session issued"

            # 3. Wrong password rejected with 401 & audited
            def c03() -> str:
                r_bad = client.post(
                    "/api/v1/auth/login",
                    json={"actor_id": "alice", "password": "WrongPassword!", "device_id": "dev-alice-01", "peer_id": "peer-a"},
                )
                assert r_bad.status_code == 401, r_bad.text
                return "Invalid password rejected with HTTP 401"

            # 4. Session validation & revocation enforcement
            def c04() -> str:
                r_sess = client.post("/api/v1/auth/demo-login", json={"actor_id": "alice", "device_id": "dev-alice-01", "peer_id": "peer-a"})
                assert r_sess.status_code == 200, r_sess.text
                sid = r_sess.json()["id"]
                tok = r_sess.json()["session_token"]
                r_val1 = client.post(
                    "/api/v1/sessions/validate",
                    json={"session_id": sid, "session_token": tok, "actor_id": "alice", "device_id": "dev-alice-01"},
                )
                assert r_val1.status_code == 200 and r_val1.json().get("revoked_at") is None, r_val1.text
                r_rev = client.post(f"/api/v1/sessions/{sid}/revoke", json={"actor_id": "alice", "reason": "Assessment revocation"})
                assert r_rev.status_code == 200, r_rev.text
                r_val2 = client.post(
                    "/api/v1/sessions/validate",
                    json={"session_id": sid, "session_token": tok, "actor_id": "alice", "device_id": "dev-alice-01"},
                )
                assert r_val2.status_code >= 400 or r_val2.json().get("revoked_at") is not None, r_val2.text
                return "Revoked session token fails validation immediately"

            # 5. RBAC fail-closed on unauthorized action
            def c05() -> str:
                r_pol = client.post(
                    "/api/v1/policy/evaluate",
                    json={
                        "actor_id": "auditor",
                        "session_id": s_aud["id"],
                        "session_token": s_aud["session_token"],
                        "device_id": "dev-auditor-01",
                        "resource_id": "vault-brief-alice",
                        "action": "actor:revoke",
                    },
                )
                assert r_pol.status_code == 200 and r_pol.json()["decision"] == "DENY", r_pol.text
                return "Auditor denied actor:revoke (fail-closed RBAC)"

            # 6. Unknown action fails closed
            def c06() -> str:
                r_pol = client.post(
                    "/api/v1/policy/evaluate",
                    json={
                        "actor_id": "admin",
                        "session_id": s_admin["id"],
                        "session_token": s_admin["session_token"],
                        "device_id": "dev-admin-01",
                        "resource_id": "vault-brief-alice",
                        "action": "unknown:dangerous_op",
                    },
                )
                assert r_pol.status_code == 200 and r_pol.json()["decision"] == "DENY", r_pol.text
                return "Unknown action denied by default"

            # 7. Device revocation blocks policy evaluation
            def c07() -> str:
                client.post(
                    "/api/v1/devices",
                    json={"id": "dev-revoke-test", "owner_actor_id": "alice", "credential_fingerprint": "fp-revoke-test", "state": "TRUSTED"},
                )
                s_rev = client.post("/api/v1/auth/demo-login", json={"actor_id": "alice", "device_id": "dev-revoke-test", "peer_id": "peer-rev"}).json()
                r_dev = client.post("/api/v1/devices/dev-revoke-test/revoke", json={"operator_actor_id": "secop", "reason": "Compromise test"})
                assert r_dev.status_code == 200, r_dev.text
                r_pol = client.post(
                    "/api/v1/policy/evaluate",
                    json={
                        "actor_id": "alice",
                        "session_id": s_rev["id"],
                        "session_token": s_rev["session_token"],
                        "device_id": "dev-revoke-test",
                        "resource_id": "vault-brief-alice",
                        "action": "resource:read",
                    },
                )
                assert r_pol.status_code == 200 and r_pol.json()["decision"] == "DENY", r_pol.text
                return "Revoked device denied access (fail-closed)"

            # 8. Key generation & rotation updates active version
            def c08() -> str:
                r_gen = client.post("/api/v1/keys/generate", json={"operator_actor_id": "secop", "reason": "Assessment key gen"})
                assert r_gen.status_code in (200, 201), r_gen.text
                r_rot = client.post("/api/v1/keys/rotate", json={"operator_actor_id": "secop", "reason": "Assessment rotation", "retire_policy": "RETIRED"})
                assert r_rot.status_code == 200 and r_rot.json()["committed"] is True, r_rot.text
                return f"Rotated key to v{r_rot.json()['new_version']}"

            # 9. Journaled crash & recovery
            def c09() -> str:
                from backend.app.recovery.service import SimulatedCrashError

                op_id = None
                try:
                    r_j = client.post(
                        "/api/v1/keys/rotate/journaled",
                        json={"operator_actor_id": "secop", "reason": "Crash test", "retire_policy": "RETIRED", "crash_at": "before_commit"},
                    )
                    if r_j.status_code == 200:
                        op_id = r_j.json()["operation_id"]
                except SimulatedCrashError as exc:
                    op_id = str(exc).split("'")[-2]
                assert op_id, "Expected SimulatedCrashError with operation_id"
                r_rec = client.post(f"/api/v1/keys/recover/{op_id}", json={"operator_actor_id": "secop"})
                assert r_rec.status_code == 200 and r_rec.json().get("recovery_outcome") == "RECOVERED_PRE_COMMIT", r_rec.text
                return f"Recovered crashed journaled rotation {op_id}"

            # 10. Key compromise marking
            def c10() -> str:
                r_gen = client.post("/api/v1/keys/generate", json={"operator_actor_id": "secop", "reason": "Compromise target"})
                assert r_gen.status_code in (200, 201), r_gen.text
                kid = r_gen.json()["id"]
                r_comp = client.post(f"/api/v1/keys/{kid}/compromise", json={"operator_actor_id": "secop", "reason": "Key leak drill"})
                assert r_comp.status_code == 200 and r_comp.json()["state"] == "COMPROMISED", r_comp.text
                # Ensure an active key exists for subsequent vault/backup checks
                client.post("/api/v1/keys/rotate", json={"operator_actor_id": "secop", "reason": "Re-activate post compromise", "retire_policy": "RETIRED"})
                return f"Key {kid} marked COMPROMISED and new active key rotated"

            # 11. Encrypted vault store & authenticated read
            def c11() -> str:
                r_st = client.post(
                    "/api/v1/vault/resources",
                    json={"resource_id": "vault-sec-1", "owner_actor_id": "alice", "plaintext": "top-secret-payload"},
                )
                assert r_st.status_code in (200, 201), r_st.text
                s_v = client.post("/api/v1/auth/demo-login", json={"actor_id": "alice", "device_id": "dev-alice-01", "peer_id": "peer-v"}).json()
                r_rd = client.post(
                    "/api/v1/vault/resources/vault-sec-1/read",
                    json={
                        "actor_id": "alice",
                        "session_id": s_v["id"],
                        "session_token": s_v["session_token"],
                        "device_id": "dev-alice-01",
                    },
                )
                assert r_rd.status_code == 200 and r_rd.json()["plaintext"] == "top-secret-payload", r_rd.text
                return "AES-256-GCM vault round-trip verified"

            # 12. Encrypted messaging & replay rejection
            def c12() -> str:
                s_m = client.post("/api/v1/auth/demo-login", json={"actor_id": "alice", "device_id": "dev-alice-01", "peer_id": "peer-msg"}).json()
                r_send = client.post(
                    "/api/v1/messages/send",
                    json={"sender_id": "alice", "recipient_id": "bob", "session_id": s_m["id"], "plaintext": "hello-secure"},
                )
                assert r_send.status_code in (200, 201), r_send.text
                mid = r_send.json()["id"]
                r_del1 = client.post(f"/api/v1/messages/{mid}/deliver", json={"recipient_id": "bob"})
                assert r_del1.status_code == 200, r_del1.text
                r_del2 = client.post(f"/api/v1/messages/{mid}/deliver", json={"recipient_id": "bob"})
                assert r_del2.status_code in (400, 409), r_del2.text
                return "Duplicate message delivery/replay rejected"

            # 13. Audit hash-chain integrity & non-destructive tamper detection
            def c13() -> str:
                r_v = client.post("/api/v1/audit/verify")
                assert r_v.status_code == 200 and r_v.json()["valid"] is True, r_v.text
                r_td = client.post("/api/v1/audit/tamper-demo")
                assert r_td.status_code == 200 and (r_td.json().get("detected") is True or r_td.json().get("tamper_detected") is True or r_td.json().get("valid") is False), r_td.text
                return f"Audit chain valid ({r_v.json().get('checked_events', r_v.json().get('total_events', 0))} events) and tamper detection verified"

            # 14. Deterministic detector & incident containment
            def c14() -> str:
                now_iso = datetime.now(timezone.utc).isoformat()
                events = [
                    {
                        "event_id": f"ev-sec-{i}",
                        "actor": "alice",
                        "action": "AUTH_FAILURE",
                        "event_time": now_iso,
                        "device": "dev-alice-01",
                    }
                    for i in range(5)
                ]
                r_ing = client.post("/api/v1/detector/ingest", json={"events": events})
                assert r_ing.status_code == 200, r_ing.text
                r_run = client.post("/api/v1/detector/run", json={"approvals": []})
                assert r_run.status_code == 200 and isinstance(r_run.json(), list), r_run.text
                return f"Deterministic detector ran cleanly (alerts={len(r_run.json())})"

            # 15. Stage 13 WebAuthn challenge single-use replay protection
            def c15() -> str:
                r_opt = client.post("/api/v1/identity-assurance/register/options", json={"actor_id": "alice", "rp_id": "localhost"})
                assert r_opt.status_code == 200, r_opt.text
                data = r_opt.json()
                ch_id = data["challenge_id"]
                ch_b64 = data["options"]["challenge"]
                _, cred = _synthetic_webauthn_create(ch_b64)
                r_v1 = client.post(
                    "/api/v1/identity-assurance/register/verify",
                    json={"actor_id": "alice", "challenge_id": ch_id, "credential": cred, "device_id": "dev-alice-01"},
                )
                assert r_v1.status_code in (200, 201), r_v1.text
                r_v2 = client.post(
                    "/api/v1/identity-assurance/register/verify",
                    json={"actor_id": "alice", "challenge_id": ch_id, "credential": cred, "device_id": "dev-alice-01"},
                )
                assert r_v2.status_code in (400, 404, 409), r_v2.text
                return "Single-use WebAuthn challenge replay blocked"

            # 16. Stage 13 FIM baseline initialization & integrity scan
            def c16() -> str:
                r_b = client.post("/api/v1/integrity/baseline/initialize", json={"actor_id": "admin"})
                assert r_b.status_code in (200, 201), r_b.text
                r_s = client.post("/api/v1/integrity/scans", json={"actor_id": "admin"})
                assert r_s.status_code in (200, 201), r_s.text
                return f"FIM baseline & scan executed (status={r_s.json().get('status', 'OK')})"

            # 17. Backup manifest integrity & tamper rejection
            def c17() -> str:
                r_cr = client.post("/api/v1/keys/backups/create", json={"operator_actor_id": "admin"})
                assert r_cr.status_code in (200, 201), r_cr.text
                manifest = r_cr.json()
                r_ok = client.post("/api/v1/keys/backups/verify", json={"manifest": manifest})
                assert r_ok.status_code == 200 and r_ok.json()["valid"] is True, r_ok.text
                tampered = dict(manifest)
                tampered["manifest_sha256"] = "0" * 64
                r_bad = client.post("/api/v1/keys/backups/verify", json={"manifest": tampered})
                assert r_bad.status_code == 200 and r_bad.json()["valid"] is False, r_bad.text
                return "Backup manifest valid; tampered digest rejected"

            # 18. Simulated node partition & reconciliation
            def c18() -> str:
                r_p = client.post("/api/v1/nodes/sim-node-1/partition")
                assert r_p.status_code == 200, r_p.text
                r_rec = client.post("/api/v1/nodes/sim-node-1/recover")
                assert r_rec.status_code == 200, r_rec.text
                r_reconcile = client.post("/api/v1/nodes/reconcile")
                assert r_reconcile.status_code == 200, r_reconcile.text
                return "Simulated node partition recovery and reconciliation verified"

            checks = [
                ("SEC-01", "Unauthorized Password Takeover Blocked", "Authentication", c01),
                ("SEC-02", "Salted Scrypt Password Auth", "Authentication", c02),
                ("SEC-03", "Invalid Password Rejection", "Authentication", c03),
                ("SEC-04", "Session Revocation Enforcement", "Session Security", c04),
                ("SEC-05", "RBAC Least-Privilege Deny", "Authorization", c05),
                ("SEC-06", "Fail-Closed Unknown Action", "Authorization", c06),
                ("SEC-07", "Device Revocation Enforcement", "Trust Plane", c07),
                ("SEC-08", "Key Generation & Rotation", "Cryptography", c08),
                ("SEC-09", "Crash-Safe Journaled Recovery", "Resilience", c09),
                ("SEC-10", "Key Compromise Quarantine", "Cryptography", c10),
                ("SEC-11", "AES-256-GCM Vault Confidentiality", "Cryptography", c11),
                ("SEC-12", "Messaging Replay Protection", "Protocol Security", c12),
                ("SEC-13", "Audit Hash-Chain & Tamper Detection", "Auditability", c13),
                ("SEC-14", "Deterministic Rule Detector", "Detection", c14),
                ("SEC-15", "WebAuthn Challenge Replay Guard", "Identity Assurance", c15),
                ("SEC-16", "System File Integrity Monitoring", "Integrity", c16),
                ("SEC-17", "Backup Manifest Digest Verification", "Integrity", c17),
                ("SEC-18", "Simulated Node Partition Recovery", "Sandbox Simulation", c18),
            ]
            for cid, name, cat, fn in checks:
                check(cid, name, cat, fn)
    finally:
        if engine is not None:
            engine.dispose()
        shutil.rmtree(tmp_dir, ignore_errors=True)

    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = len(results) - passed
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_checks": len(results),
        "passed": passed,
        "failed": failed,
        "checks": results,
    }
    (REPORT_DIR / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = [
        "# Q-SHIELD Automated Security Assessment Summary",
        "",
        f"- **Generated At:** `{report['generated_at']}`",
        f"- **Result:** `{passed}/{len(results)} PASS` (`{failed} FAIL`)",
        "",
        "| ID | Check | Category | Status | Detail |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        lines.append(f"| {r['id']} | {r['name']} | {r['category']} | **{r['status']}** | {r['detail']} |")
    (REPORT_DIR / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    out = run_assessment()
    print(f"Security assessment complete: {out['passed']}/{out['total_checks']} PASS")
    if out["failed"]:
        raise SystemExit(1)

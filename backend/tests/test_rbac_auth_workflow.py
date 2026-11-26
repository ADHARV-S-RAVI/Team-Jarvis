"""Comprehensive security tests for User/Employee/Admin RBAC auth, 256-bit session secrets, file access, and WebAuthn."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import Actor, AuditEvent, AuthSession
from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app
from backend.app.services.rbac_auth_service import create_protected_file, provision_rbac_account


def test_rbac_auth_sessions_secrets_and_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("QSHIELD_ENABLE_DEV_DEMO_AUTH", "false")
    from backend.app.config import get_settings

    get_settings.cache_clear()
    db_file = tmp_path / "rbac_auth.db"
    db_url = f"sqlite:///{db_file.as_posix()}"

    alembic_cfg = Config("backend/alembic.ini")
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

    with TestingSession() as db:
        provision_rbac_account(
            db,
            actor_id="user_u1",
            display_label="Standard User",
            email="u1@qshield.local",
            role="User",
            password="UserSecret#2026",
            device_id="dev-u1",
            operator_actor_id="bootstrap",
            correlation_id="seed-1",
        )
        provision_rbac_account(
            db,
            actor_id="emp_e1",
            display_label="Ops Employee",
            email="e1@qshield.local",
            role="Employee",
            password="EmpSecret#2026",
            device_id="dev-e1",
            operator_actor_id="bootstrap",
            correlation_id="seed-2",
        )
        provision_rbac_account(
            db,
            actor_id="adm_a1",
            display_label="Security Admin",
            email="a1@qshield.local",
            role="Admin",
            password="AdminSecret#2026",
            device_id="dev-a1",
            operator_actor_id="bootstrap",
            correlation_id="seed-3",
        )
        f_user = create_protected_file(
            db,
            name="user_brief.txt",
            classification="INTERNAL",
            required_role="User",
            assigned_actor_id="user_u1",
            content_text="USER_PERSONAL_DATA",
            operator_actor_id="adm_a1",
            correlation_id="seed-f1",
        )
        f_emp = create_protected_file(
            db,
            name="employee_runbook.txt",
            classification="RESTRICTED",
            required_role="Employee",
            assigned_actor_id="emp_e1",
            content_text="EMPLOYEE_OPS_RUNBOOK",
            operator_actor_id="adm_a1",
            correlation_id="seed-f2",
        )
        f_adm = create_protected_file(
            db,
            name="admin_master_policy.txt",
            classification="SECRET",
            required_role="Admin",
            assigned_actor_id=None,
            content_text="ADMIN_POLICY_SECRET",
            operator_actor_id="adm_a1",
            correlation_id="seed-f3",
        )

    with TestClient(app) as client:
        # 0. Demo login bypass is disabled by default (403)
        r_demo = client.post(
            "/api/v1/auth/demo-login",
            json={"actor_id": "user_u1", "device_id": "dev-u1", "peer_id": "p"},
        )
        assert r_demo.status_code == 403

        # 0b. Public User registration creates User role only & rejects duplicate email / mismatch
        r_mismatch = client.post(
            "/api/v1/auth/register",
            json={
                "actor_id": "self_bad",
                "display_label": "Bad",
                "email": "bad@qshield.local",
                "password": "SelfPassword#2026",
                "confirm_password": "DifferentPassword#2026",
            },
        )
        assert r_mismatch.status_code == 400

        r_reg = client.post(
            "/api/v1/auth/register",
            json={
                "actor_id": "self_user1",
                "display_label": "Self User",
                "email": "self1@qshield.local",
                "password": "SelfPassword#2026",
                "confirm_password": "SelfPassword#2026",
            },
        )
        assert r_reg.status_code == 201 and r_reg.json()["role"] == "User"

        r_dup_email = client.post(
            "/api/v1/auth/register",
            json={
                "actor_id": "self_user2",
                "display_label": "Self User 2",
                "email": "self1@qshield.local",
                "password": "SelfPassword#2026",
                "confirm_password": "SelfPassword#2026",
            },
        )
        assert r_dup_email.status_code == 409

        # 1. Valid User, Employee, and Admin login (by username & email)
        r_u = client.post(
            "/api/v1/auth/role-login",
            json={"identifier": "u1@qshield.local", "password": "UserSecret#2026", "expected_role": "User"},
        )
        assert r_u.status_code == 200, r_u.text
        u_sess = r_u.json()
        assert u_sess["role"] == "User"
        assert u_sess["session_secret_bound"] is True
        assert "session_secret" not in u_sess and "session_secret_hash" not in u_sess

        r_e = client.post(
            "/api/v1/auth/role-login",
            json={"identifier": "emp_e1", "password": "EmpSecret#2026", "expected_role": "Employee"},
        )
        assert r_e.status_code == 200, r_e.text
        e_sess = r_e.json()

        r_a = client.post(
            "/api/v1/auth/role-login",
            json={"identifier": "adm_a1", "password": "AdminSecret#2026", "expected_role": "Admin"},
        )
        assert r_a.status_code == 200, r_a.text
        a_sess = r_a.json()

        # 2. Unique session secrets & no session fixation (new login -> new session_id & secret hash)
        r_u2 = client.post(
            "/api/v1/auth/role-login",
            json={"identifier": "user_u1", "password": "UserSecret#2026", "expected_role": "User"},
        )
        assert r_u2.status_code == 200
        u_sess2 = r_u2.json()
        assert u_sess2["session_id"] != u_sess["session_id"]
        with TestingSession() as db:
            s1 = db.get(AuthSession, u_sess["session_id"])
            s2 = db.get(AuthSession, u_sess2["session_id"])
            assert s1 is not None and s2 is not None
            assert s1.session_secret_hash and s2.session_secret_hash
            assert s1.session_secret_hash != s2.session_secret_hash

        # 3. Role spoofing rejected (User claiming Admin -> 403)
        r_spoof = client.post(
            "/api/v1/auth/role-login",
            json={"identifier": "user_u1", "password": "UserSecret#2026", "expected_role": "Admin"},
        )
        assert r_spoof.status_code == 403

        # 4. Incorrect password & unknown account rejected (401)
        assert (
            client.post(
                "/api/v1/auth/role-login",
                json={"identifier": "user_u1", "password": "WrongPassword", "expected_role": "User"},
            ).status_code
            == 401
        )
        assert (
            client.post(
                "/api/v1/auth/role-login",
                json={"identifier": "nonexistent", "password": "UserSecret#2026", "expected_role": "User"},
            ).status_code
            == 401
        )

        # 5. Authorization & Protected File Access
        u_headers = {"X-Session-Id": u_sess["session_id"], "Authorization": f"Bearer {u_sess['session_token']}"}
        e_headers = {"X-Session-Id": e_sess["session_id"], "Authorization": f"Bearer {e_sess['session_token']}"}
        a_headers = {"X-Session-Id": a_sess["session_id"], "Authorization": f"Bearer {a_sess['session_token']}"}

        # User can download own User file, denied Employee & Admin files
        assert client.get(f"/api/v1/files/{f_user.id}/download", headers=u_headers).status_code == 200
        assert client.get(f"/api/v1/files/{f_emp.id}/download", headers=u_headers).status_code == 403
        assert client.get(f"/api/v1/files/{f_adm.id}/download", headers=u_headers).status_code == 403
        assert client.get("/api/v1/admin/users", headers=u_headers).status_code == 403

        # Employee can download Employee file, denied Admin file & Admin APIs
        assert client.get(f"/api/v1/files/{f_emp.id}/download", headers=e_headers).status_code == 200
        assert client.get(f"/api/v1/files/{f_adm.id}/download", headers=e_headers).status_code == 403
        assert client.get("/api/v1/admin/users", headers=e_headers).status_code == 403

        # Admin can access Admin APIs & all files
        assert client.get("/api/v1/admin/users", headers=a_headers).status_code == 200
        assert client.get(f"/api/v1/files/{f_adm.id}/download", headers=a_headers).status_code == 200

        # 6. Camera & WebAuthn checkpoints
        r_cam = client.post(
            "/api/v1/auth/camera-checkpoint",
            json={"consent_granted": True, "action": "COMPLETED"},
            headers=u_headers,
        )
        assert (
            r_cam.status_code == 200
            and r_cam.json()["camera_preview_completed"] is True
            and r_cam.json()["face_recognition"] == "NOT_IMPLEMENTED"
        )

        # 7. Logout invalidates session & clears session_secret_hash
        r_out = client.post("/api/v1/auth/logout", headers=u_headers)
        assert r_out.status_code == 200
        assert client.get("/api/v1/auth/session-status", headers=u_headers).status_code == 401
        with TestingSession() as db:
            s_out = db.get(AuthSession, u_sess["session_id"])
            assert s_out is not None and s_out.revoked_at is not None and s_out.session_secret_hash is None

        # 8. Expired session rejected
        with TestingSession() as db:
            s_exp = db.get(AuthSession, e_sess["session_id"])
            assert s_exp is not None
            s_exp.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
            db.commit()
        assert client.get("/api/v1/auth/session-status", headers=e_headers).status_code == 401

        # 9. Repeated failed logins trigger temporary lockout (429)
        for _ in range(4):
            client.post(
                "/api/v1/auth/role-login",
                json={"identifier": "user_u1", "password": "BadPassword", "expected_role": "User"},
            )
        r_lock = client.post(
            "/api/v1/auth/role-login",
            json={"identifier": "user_u1", "password": "UserSecret#2026", "expected_role": "User"},
        )
        assert r_lock.status_code == 429

        # 10. Audit ledger never leaks raw passwords or session secrets
        with TestingSession() as db:
            audits = db.execute(select(AuditEvent)).scalars().all()
            joined = " ".join(f"{a.action} {a.reason} {a.metadata_json}" for a in audits)
            assert "UserSecret#2026" not in joined
            assert "AdminSecret#2026" not in joined
            assert len(audits) >= 10

    engine.dispose()


def test_passkey_login_and_removal_guard(tmp_path: Path, monkeypatch) -> None:
    import base64
    import hashlib
    import json
    import os
    import struct
    import cbor2
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec

    monkeypatch.setenv("QSHIELD_ENABLE_DEV_DEMO_AUTH", "false")
    from backend.app.config import get_settings

    get_settings.cache_clear()
    db_file = tmp_path / "passkey_login.db"
    db_url = f"sqlite:///{db_file.as_posix()}"

    alembic_cfg = Config("backend/alembic.ini")
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

    def b64u(b: bytes) -> str:
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    with TestingSession() as db:
        provision_rbac_account(
            db,
            actor_id="pk_user",
            display_label="Passkey User",
            email="pk@qshield.local",
            role="User",
            password="TempPassword#2026",
            device_id="dev-pk-user",
            operator_actor_id="bootstrap",
            correlation_id="pk-seed",
        )

    with TestClient(app) as client:
        # Register synthetic P-256 passkey
        r_opt = client.post("/api/v1/identity-assurance/register/options", json={"actor_id": "pk_user", "rp_id": "localhost"})
        assert r_opt.status_code == 200
        ch_id = r_opt.json()["challenge_id"]
        ch_b64 = r_opt.json()["options"]["challenge"]

        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key().public_numbers()
        cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: pub.x.to_bytes(32, "big"), -3: pub.y.to_bytes(32, "big")})
        cred_id = os.urandom(16)
        rp_hash = hashlib.sha256(b"localhost").digest()
        auth_data = rp_hash + bytes([0x45]) + struct.pack(">I", 1) + (b"\x00" * 16) + struct.pack(">H", len(cred_id)) + cred_id + cose_key
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = json.dumps({"type": "webauthn.create", "challenge": ch_b64, "origin": "http://localhost:5173"}).encode("utf-8")

        r_reg = client.post(
            "/api/v1/identity-assurance/register/verify",
            json={
                "actor_id": "pk_user",
                "challenge_id": ch_id,
                "device_id": "dev-pk-user",
                "rp_id": "localhost",
                "origin": "http://localhost:5173",
                "credential": {
                    "id": b64u(cred_id),
                    "rawId": b64u(cred_id),
                    "type": "public-key",
                    "response": {"clientDataJSON": b64u(client_data), "attestationObject": b64u(att_obj)},
                },
            },
        )
        assert r_reg.status_code == 201, r_reg.text
        cred_record_id = r_reg.json()["id"]

        # Passkey login (options -> signed assertion -> verify -> authenticated session)
        r_aopt = client.post("/api/v1/auth/passkey-login/options", json={"identifier": "pk@qshield.local", "rp_id": "localhost"})
        assert r_aopt.status_code == 200, r_aopt.text
        ach_id = r_aopt.json()["challenge_id"]
        ach_b64 = r_aopt.json()["options"]["challenge"]

        auth_data_get = rp_hash + bytes([0x05]) + struct.pack(">I", 2)
        client_data_get = json.dumps({"type": "webauthn.get", "challenge": ach_b64, "origin": "http://localhost:5173"}).encode("utf-8")
        sig = priv.sign(auth_data_get + hashlib.sha256(client_data_get).digest(), ec.ECDSA(hashes.SHA256()))
        assertion_payload = {
            "identifier": "pk@qshield.local",
            "challenge_id": ach_id,
            "rp_id": "localhost",
            "origin": "http://localhost:5173",
            "credential": {
                "id": b64u(cred_id),
                "rawId": b64u(cred_id),
                "type": "public-key",
                "response": {
                    "clientDataJSON": b64u(client_data_get),
                    "authenticatorData": b64u(auth_data_get),
                    "signature": b64u(sig),
                },
            },
        }
        r_aver = client.post("/api/v1/auth/passkey-login/verify", json=assertion_payload)
        assert r_aver.status_code == 200, r_aver.text
        assert r_aver.json()["verification_method"] == "WEBAUTHN"
        assert r_aver.json()["session_secret_bound"] is True

        # Replay of same challenge must fail (401/403)
        r_rep = client.post("/api/v1/auth/passkey-login/verify", json=assertion_payload)
        assert r_rep.status_code in (401, 403)

        # Removal guard: if password_hash is cleared, removing the only passkey is blocked (400)
        with TestingSession() as db:
            u = db.get(Actor, "pk_user")
            assert u is not None
            u.password_hash = None
            db.commit()
        r_rem = client.post(
            f"/api/v1/identity-assurance/credentials/{cred_record_id}/revoke",
            json={"actor_id": "pk_user", "reason": "Test removal guard", "delete_record": False},
        )
        assert r_rem.status_code == 400
    engine.dispose()

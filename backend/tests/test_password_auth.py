"""Comprehensive security tests for salted scrypt password auth, authorization, rate limiting, and session revocation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import Actor, AuthSession
from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


def test_password_auth_security_controls(tmp_path: Path) -> None:
    db_file = tmp_path / "password_auth_sec.db"
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

    with TestClient(app) as client:
        assert client.post("/api/v1/simulation/reset").status_code == 200

        # 1. Unauthorized password assignment without session/admin must fail (403)
        r_unauth = client.post(
            "/api/v1/auth/set-password",
            json={"actor_id": "alice", "password": "AttackerPassword!1"},
        )
        assert r_unauth.status_code == 403

        # Create alice's demo session for initial password bootstrap
        s_alice = client.post(
            "/api/v1/auth/demo-login",
            json={"actor_id": "alice", "device_id": "dev-alice-01", "peer_id": "peer-test"},
        ).json()

        # 2. Cross-actor password assignment using alice's session for bob must fail (403)
        r_cross = client.post(
            "/api/v1/auth/set-password",
            json={
                "actor_id": "bob",
                "password": "CrossActorPassword!1",
                "session_id": s_alice["id"],
                "session_token": s_alice["session_token"],
            },
        )
        assert r_cross.status_code == 403

        # 3. Authorized initial password assignment for alice
        r_set = client.post(
            "/api/v1/auth/set-password",
            json={
                "actor_id": "alice",
                "password": "SecurePassphrase#2026",
                "session_id": s_alice["id"],
                "session_token": s_alice["session_token"],
            },
        )
        assert r_set.status_code == 200
        assert r_set.json()["algorithm"] == "scrypt"

        # 4. Password change must revoke existing sessions
        r_old_val = client.post(
            "/api/v1/sessions/validate",
            json={
                "session_id": s_alice["id"],
                "session_token": s_alice["session_token"],
                "actor_id": "alice",
                "device_id": "dev-alice-01",
            },
        )
        assert r_old_val.status_code >= 400 or r_old_val.json().get("revoked_at") is not None

        # 5. Password replacement without current_password or Admin must fail (403)
        r_rep_fail = client.post(
            "/api/v1/auth/set-password",
            json={"actor_id": "alice", "password": "ReplacedWithoutAuth!1"},
        )
        assert r_rep_fail.status_code == 403

        # 6. Correct password login succeeds
        r_ok = client.post(
            "/api/v1/auth/login",
            json={
                "actor_id": "alice",
                "password": "SecurePassphrase#2026",
                "device_id": "dev-alice-01",
                "peer_id": "peer-test",
            },
        )
        assert r_ok.status_code == 200
        login_sess = r_ok.json()
        assert login_sess["session_token"]

        # 7. Session revocation invalidates session
        assert (
            client.post(
                f"/api/v1/sessions/{login_sess['id']}/revoke",
                json={"actor_id": "alice", "reason": "Test revoke"},
            ).status_code
            == 200
        )
        r_rev_val = client.post(
            "/api/v1/sessions/validate",
            json={
                "session_id": login_sess["id"],
                "session_token": login_sess["session_token"],
                "actor_id": "alice",
                "device_id": "dev-alice-01",
            },
        )
        assert r_rev_val.status_code >= 400 or r_rev_val.json().get("revoked_at") is not None

        # 8. Session expiration invalidates session
        s_exp = client.post(
            "/api/v1/auth/login",
            json={
                "actor_id": "alice",
                "password": "SecurePassphrase#2026",
                "device_id": "dev-alice-01",
                "peer_id": "peer-exp",
            },
        ).json()
        with TestingSession() as db:
            row = db.get(AuthSession, s_exp["id"])
            assert row is not None
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
            db.commit()
        r_exp_val = client.post(
            "/api/v1/sessions/validate",
            json={
                "session_id": s_exp["id"],
                "session_token": s_exp["session_token"],
                "actor_id": "alice",
                "device_id": "dev-alice-01",
            },
        )
        assert r_exp_val.status_code >= 400

        # 9. Disabled account rejected during login
        with TestingSession() as db:
            alice = db.get(Actor, "alice")
            assert alice is not None
            alice.enabled = False
            db.commit()
        r_dis = client.post(
            "/api/v1/auth/login",
            json={
                "actor_id": "alice",
                "password": "SecurePassphrase#2026",
                "device_id": "dev-alice-01",
                "peer_id": "peer-dis",
            },
        )
        assert r_dis.status_code == 401
        with TestingSession() as db:
            alice = db.get(Actor, "alice")
            assert alice is not None
            alice.enabled = True
            db.commit()

        # 10. Incorrect password & login rate limiting (1 prior failure + 4 failures -> 6th returns 429)
        for _ in range(4):
            r_bad = client.post(
                "/api/v1/auth/login",
                json={
                    "actor_id": "alice",
                    "password": "WrongPassword!",
                    "device_id": "dev-alice-01",
                    "peer_id": "peer-rl",
                },
            )
            assert r_bad.status_code == 401
        r_429 = client.post(
            "/api/v1/auth/login",
            json={
                "actor_id": "alice",
                "password": "SecurePassphrase#2026",
                "device_id": "dev-alice-01",
                "peer_id": "peer-rl",
            },
        )
        assert r_429.status_code == 429
    engine.dispose()

"""Integration tests for FastAPI app, Alembic migrations, SQLite persistence, and Stage 2 API."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.orm import sessionmaker

from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


@pytest.fixture()
def migrated_env(tmp_path: Path):
    db_file = tmp_path / "qshield_stage2_test.db"
    db_url = f"sqlite:///{db_file}"

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
    client = TestClient(app)
    try:
        yield client, engine, db_url
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_alembic_migration_and_sqlite_pragmas(migrated_env) -> None:
    client, engine, _ = migrated_env

    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    expected_tables = {
        "actors",
        "role_permissions",
        "devices",
        "sessions",
        "key_metadata",
        "resources",
        "revocation_tombstones",
        "incident_policy_denials",
        "audit_events",
        "alembic_version",
    }
    assert expected_tables.issubset(tables)

    with engine.connect() as conn:
        fk = conn.execute(text("PRAGMA foreign_keys")).scalar_one()
        journal = conn.execute(text("PRAGMA journal_mode")).scalar_one()
        assert fk == 1
        assert str(journal).lower() == "wal"

    health = client.get("/api/v1/health")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["database"] == "ok"


def test_end_to_end_identity_device_session_resource_and_revocation(migrated_env) -> None:
    client, _, db_url = migrated_env

    # Create Alice and Bob
    r1 = client.post("/api/v1/identities", json={"id": "alice", "display_label": "Alice", "role": "Owner/User"})
    assert r1.status_code == 201
    r2 = client.post("/api/v1/identities", json={"id": "bob", "display_label": "Bob", "role": "Owner/User"})
    assert r2.status_code == 201

    assert client.get("/api/v1/identities/alice").status_code == 200

    # Register devices
    d1 = client.post(
        "/api/v1/devices",
        json={"id": "dev-a1", "owner_actor_id": "alice", "credential_fingerprint": "sha256:alice-dev-1"},
    )
    assert d1.status_code == 201
    d2 = client.post(
        "/api/v1/devices",
        json={"id": "dev-b1", "owner_actor_id": "bob", "credential_fingerprint": "sha256:bob-dev-1"},
    )
    assert d2.status_code == 201
    assert client.get("/api/v1/devices/dev-a1").status_code == 200

    # Issue sessions
    s_alice = client.post(
        "/api/v1/sessions",
        json={"actor_id": "alice", "device_id": "dev-a1", "peer_id": "vault-service"},
    )
    assert s_alice.status_code == 201
    alice_sess = s_alice.json()
    assert "session_token" in alice_sess

    # Validate session
    val_ok = client.post(
        "/api/v1/sessions/validate",
        json={
            "session_id": alice_sess["id"],
            "session_token": alice_sess["session_token"],
            "actor_id": "alice",
            "device_id": "dev-a1",
            "peer_id": "vault-service",
        },
    )
    assert val_ok.status_code == 200

    s_bob = client.post(
        "/api/v1/sessions",
        json={"actor_id": "bob", "device_id": "dev-b1", "peer_id": "vault-service"},
    )
    assert s_bob.status_code == 201
    bob_sess = s_bob.json()

    # Register resources
    res_a = client.post(
        "/api/v1/resources",
        json={"id": "doc-alice", "owner_actor_id": "alice", "content_ref": "vault://alice/1"},
    )
    assert res_a.status_code == 201

    # Valid owner read -> 200
    read_ok = client.get(
        "/api/v1/resources/doc-alice",
        params={"actor_id": "alice", "session_id": alice_sess["id"], "device_id": "dev-a1"},
    )
    assert read_ok.status_code == 200
    assert read_ok.json()["owner_actor_id"] == "alice"

    # Cross-user IDOR read -> 403
    read_idor = client.get(
        "/api/v1/resources/doc-alice",
        params={"actor_id": "bob", "session_id": bob_sess["id"], "device_id": "dev-b1"},
    )
    assert read_idor.status_code == 403
    assert read_idor.json()["detail"]["reason_code"] == "RESOURCE_OWNERSHIP_DENIED"

    # Revoke Alice -> tombstone created and subsequent evaluation denies
    rev = client.post(
        "/api/v1/revocations",
        json={"subject_type": "actor", "subject_id": "alice", "reason": "Lost device incident"},
    )
    assert rev.status_code == 201

    rev_status = client.get("/api/v1/revocations/actor/alice")
    assert rev_status.status_code == 200
    assert rev_status.json()["revoked"] is True

    eval_after_rev = client.post(
        "/api/v1/policy/evaluate",
        json={
            "actor_id": "alice",
            "session_id": alice_sess["id"],
            "device_id": "dev-a1",
            "resource_id": "doc-alice",
            "action": "resource:read",
        },
    )
    assert eval_after_rev.status_code == 200
    assert eval_after_rev.json()["decision"] == "DENY"
    assert eval_after_rev.json()["failed_step"] == 2

    # Verify persistence across a brand-new engine/session
    fresh_engine = create_db_engine(db_url)
    try:
        with fresh_engine.connect() as conn:
            enabled = conn.execute(text("SELECT enabled FROM actors WHERE id = 'alice'")).scalar_one()
            assert enabled in (0, False)
    finally:
        fresh_engine.dispose()


def test_invalid_requests_return_structured_errors(migrated_env) -> None:
    client, _, _ = migrated_env
    bad_role = client.post(
        "/api/v1/identities",
        json={"id": "x", "display_label": "X", "role": "SuperHacker"},
    )
    assert bad_role.status_code == 422
    assert bad_role.json()["error"] == "invalid_request"
    assert "correlation_id" in bad_role.json()

    not_found = client.get("/api/v1/identities/does-not-exist")
    assert not_found.status_code == 404
    assert not_found.json()["error"] == "not_found"

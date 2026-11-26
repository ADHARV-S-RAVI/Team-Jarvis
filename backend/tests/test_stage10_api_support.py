"""Backend tests for Stage 10 console support endpoints (list, reset, demo-login, scorecard)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import sessionmaker

from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


@pytest.fixture()
def stage10_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage10_test.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("QSHIELD_KEY_STORE_DIR", str(tmp_path / "keys"))

    from backend.app.config import get_settings

    get_settings.cache_clear()

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
        yield client
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        get_settings.cache_clear()


def test_simulation_reset_demo_login_and_list_endpoints(stage10_client: TestClient) -> None:
    reset = stage10_client.post("/api/v1/simulation/reset")
    assert reset.status_code == 200
    assert reset.json()["status"] == "RESET_COMPLETE"
    assert reset.json()["seeded_actors"] == 5

    assert len(stage10_client.get("/api/v1/identities").json()) == 5
    assert len(stage10_client.get("/api/v1/devices").json()) == 3
    assert len(stage10_client.get("/api/v1/resources").json()) == 2

    login = stage10_client.post(
        "/api/v1/auth/demo-login",
        json={"actor_id": "alice", "device_id": "dev-alice-01", "peer_id": "vault"},
    )
    assert login.status_code == 200
    sess = login.json()
    assert len(stage10_client.get("/api/v1/sessions").json()) == 1

    # Authorized vault read using demo-login session
    read_ok = stage10_client.post(
        "/api/v1/vault/resources/vault-brief-alice/read",
        json={
            "actor_id": "alice",
            "session_id": sess["id"],
            "session_token": sess["session_token"],
            "device_id": "dev-alice-01",
            "peer_id": "vault",
        },
    )
    assert read_ok.status_code == 200
    assert read_ok.json()["plaintext"] == "SYNTHETIC_ALICE_CONFIDENTIAL_BRIEF"

    sc = stage10_client.get("/api/v1/evidence/scorecard")
    assert sc.status_code == 200
    assert sc.json()["forward_secrecy"] == "NOT_ESTABLISHED"
    assert sc.json()["nodes_mode"] == "SIMULATED"

"""Stage 4 tests: device lifecycle, session revocation/peer-binding, and lost-device workflow."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import AuthSession
from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


@pytest.fixture()
def stage4_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage4_test.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("QSHIELD_KEY_STORE_DIR", str(tmp_path / "keys"))

    from backend.app.config import get_settings

    get_settings.cache_clear()

    alembic_cfg = Config("backend/alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(alembic_cfg, "head")

    engine = create_db_engine(db_url)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    def make_client():
        app = create_app()

        def override_get_db():
            db = TestingSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        return TestClient(app)

    client = make_client()
    try:
        yield client, make_client, engine, db_url, TestingSession
    finally:
        engine.dispose()
        get_settings.cache_clear()


def _seed_actors_and_vault(client: TestClient) -> dict[str, dict]:
    client.post("/api/v1/identities", json={"id": "alice", "display_label": "Alice", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "bob", "display_label": "Bob", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "secop", "display_label": "SecOp", "role": "Security Operator"})

    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-alice-old", "owner_actor_id": "alice", "credential_fingerprint": "fp-alice-old-01"},
    )
    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-bob-1", "owner_actor_id": "bob", "credential_fingerprint": "fp-bob-01"},
    )

    s_alice = client.post(
        "/api/v1/sessions",
        json={"actor_id": "alice", "device_id": "dev-alice-old", "peer_id": "vault-peer"},
    ).json()
    s_bob = client.post(
        "/api/v1/sessions",
        json={"actor_id": "bob", "device_id": "dev-bob-1", "peer_id": "vault-peer"},
    ).json()

    client.post(
        "/api/v1/vault/resources",
        json={"resource_id": "res-alice", "owner_actor_id": "alice", "plaintext": "ALICE_VAULT_SECRET"},
    )
    client.post(
        "/api/v1/vault/resources",
        json={"resource_id": "res-bob", "owner_actor_id": "bob", "plaintext": "BOB_VAULT_SECRET"},
    )
    return {"alice_sess": s_alice, "bob_sess": s_bob}


def test_lost_device_workflow_replacement_and_restart_persistence(stage4_env) -> None:
    client, make_client, _, _, _ = stage4_env
    sessions = _seed_actors_and_vault(client)
    s_alice = sessions["alice_sess"]
    s_bob = sessions["bob_sess"]

    # 1. Confirmation required
    unconfirmed = client.post(
        "/api/v1/incidents/lost-device",
        json={
            "operator_actor_id": "secop",
            "device_id": "dev-alice-old",
            "reason": "Laptop stolen",
            "confirmed": False,
        },
    )
    assert unconfirmed.status_code == 400

    # 2. Authorized operator reports lost device with confirmation
    lost_resp = client.post(
        "/api/v1/incidents/lost-device",
        json={
            "operator_actor_id": "secop",
            "device_id": "dev-alice-old",
            "reason": "Laptop stolen in transit",
            "confirmed": True,
        },
    )
    assert lost_resp.status_code == 201
    body = lost_resp.json()
    assert body["device"]["state"] == "REVOKED"
    assert body["incident"]["incident_type"] == "LOST_DEVICE"
    assert body["receipt"]["policy_decision"] == "CENTRAL_TOMBSTONE_COMMITTED_DENY"
    assert len(body["receipt"]["audit_ref"]) > 0

    # Verify incident & receipt GET endpoints
    assert client.get(f"/api/v1/incidents/{body['incident']['id']}").status_code == 200
    assert client.get(f"/api/v1/incidents/{body['incident']['id']}/receipt").status_code == 200

    # 3. Old device is immediately denied
    old_read = client.post(
        "/api/v1/vault/resources/res-alice/read",
        json={
            "actor_id": "alice",
            "session_id": s_alice["id"],
            "session_token": s_alice["session_token"],
            "device_id": "dev-alice-old",
            "peer_id": "vault-peer",
        },
    )
    assert old_read.status_code == 403
    assert "ALICE_VAULT_SECRET" not in old_read.text

    # 4. Owner enrols replacement device (cannot reuse old fingerprint)
    reuse_fp = client.post(
        "/api/v1/devices/dev-alice-old/replace",
        json={
            "owner_actor_id": "alice",
            "new_device_id": "dev-alice-new",
            "new_credential_fingerprint": "fp-alice-old-01",
        },
    )
    assert reuse_fp.status_code == 400

    replace_ok = client.post(
        "/api/v1/devices/dev-alice-old/replace",
        json={
            "owner_actor_id": "alice",
            "new_device_id": "dev-alice-new",
            "new_credential_fingerprint": "fp-alice-new-02",
        },
    )
    assert replace_ok.status_code == 201
    assert replace_ok.json()["state"] == "TRUSTED"

    # New device works with new session
    s_alice_new = client.post(
        "/api/v1/sessions",
        json={"actor_id": "alice", "device_id": "dev-alice-new", "peer_id": "vault-peer"},
    ).json()
    new_read = client.post(
        "/api/v1/vault/resources/res-alice/read",
        json={
            "actor_id": "alice",
            "session_id": s_alice_new["id"],
            "session_token": s_alice_new["session_token"],
            "device_id": "dev-alice-new",
            "peer_id": "vault-peer",
        },
    )
    assert new_read.status_code == 200
    assert new_read.json()["plaintext"] == "ALICE_VAULT_SECRET"

    # 5. Simulate backend restart (brand-new FastAPI app instance): old device STILL denied
    restarted_client = make_client()
    old_after_restart = restarted_client.post(
        "/api/v1/vault/resources/res-alice/read",
        json={
            "actor_id": "alice",
            "session_id": s_alice["id"],
            "session_token": s_alice["session_token"],
            "device_id": "dev-alice-old",
            "peer_id": "vault-peer",
        },
    )
    assert old_after_restart.status_code == 403

    # 6. Unaffected authorized peer (Bob) retains access
    bob_read = restarted_client.post(
        "/api/v1/vault/resources/res-bob/read",
        json={
            "actor_id": "bob",
            "session_id": s_bob["id"],
            "session_token": s_bob["session_token"],
            "device_id": "dev-bob-1",
            "peer_id": "vault-peer",
        },
    )
    assert bob_read.status_code == 200
    assert bob_read.json()["plaintext"] == "BOB_VAULT_SECRET"


def test_suspend_restore_and_revoked_device_never_reactivated(stage4_env) -> None:
    client, _, _, _, _ = stage4_env
    _seed_actors_and_vault(client)

    # Suspend then restore works
    susp = client.post(
        "/api/v1/devices/dev-alice-old/suspend",
        json={"operator_actor_id": "secop", "reason": "Routine check"},
    )
    assert susp.status_code == 200
    assert susp.json()["state"] == "SUSPENDED"

    rest = client.post(
        "/api/v1/devices/dev-alice-old/restore",
        json={"operator_actor_id": "secop", "reason": "Verified clean"},
    )
    assert rest.status_code == 200
    assert rest.json()["state"] == "TRUSTED"

    # Revoke device -> restore MUST fail forever
    rev = client.post(
        "/api/v1/devices/dev-alice-old/revoke",
        json={"operator_actor_id": "secop", "reason": "Permanent revocation"},
    )
    assert rev.status_code == 200
    assert rev.json()["state"] == "REVOKED"

    cannot_restore = client.post(
        "/api/v1/devices/dev-alice-old/restore",
        json={"operator_actor_id": "secop", "reason": "Attempt reactivation"},
    )
    assert cannot_restore.status_code == 400


def test_unauthorized_user_cannot_perform_operator_actions(stage4_env) -> None:
    client, _, _, _, _ = stage4_env
    _seed_actors_and_vault(client)

    for path, payload in [
        ("/api/v1/devices/dev-alice-old/suspend", {"operator_actor_id": "bob", "reason": "Sneaky"}),
        ("/api/v1/devices/dev-alice-old/revoke", {"operator_actor_id": "alice", "reason": "Self"}),
        (
            "/api/v1/incidents/lost-device",
            {"operator_actor_id": "bob", "device_id": "dev-alice-old", "reason": "Fake", "confirmed": True},
        ),
    ]:
        resp = client.post(path, json=payload)
        assert resp.status_code == 403


def test_session_logout_expiry_and_cross_identity_inheritance_blocked(stage4_env) -> None:
    client, _, _, _, TestingSession = stage4_env
    sessions = _seed_actors_and_vault(client)
    s_alice = sessions["alice_sess"]

    # Cross-identity session ID reuse & wrong-peer binding fail
    cross_id = client.post(
        "/api/v1/vault/resources/res-bob/read",
        json={
            "actor_id": "bob",
            "session_id": s_alice["id"],
            "session_token": s_alice["session_token"],
            "device_id": "dev-bob-1",
            "peer_id": "vault-peer",
        },
    )
    assert cross_id.status_code == 403

    wrong_peer = client.post(
        "/api/v1/vault/resources/res-alice/read",
        json={
            "actor_id": "alice",
            "session_id": s_alice["id"],
            "session_token": s_alice["session_token"],
            "device_id": "dev-alice-old",
            "peer_id": "other-peer",
        },
    )
    assert wrong_peer.status_code == 403

    # Immediate logout / session revocation
    logout = client.post(
        f"/api/v1/sessions/{s_alice['id']}/revoke",
        json={"actor_id": "alice", "reason": "Logout"},
    )
    assert logout.status_code == 200
    assert logout.json()["revoked_at"] is not None

    after_logout = client.post(
        "/api/v1/vault/resources/res-alice/read",
        json={
            "actor_id": "alice",
            "session_id": s_alice["id"],
            "session_token": s_alice["session_token"],
            "device_id": "dev-alice-old",
            "peer_id": "vault-peer",
        },
    )
    assert after_logout.status_code == 403

    # Session expiry check
    s_bob = sessions["bob_sess"]
    with TestingSession() as db:
        sess = db.get(AuthSession, s_bob["id"])
        assert sess is not None
        sess.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
        db.commit()

    expired_read = client.post(
        "/api/v1/vault/resources/res-bob/read",
        json={
            "actor_id": "bob",
            "session_id": s_bob["id"],
            "session_token": s_bob["session_token"],
            "device_id": "dev-bob-1",
            "peer_id": "vault-peer",
        },
    )
    assert expired_read.status_code == 403

"""Stage 9 tests: AEAD recipient binding, replay ledger, loss/reordering, and peer-bound resumption."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import Message
from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


@pytest.fixture()
def stage9_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage9_test.db"
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
        yield client, TestingSession
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        get_settings.cache_clear()


def _seed_messaging_actors(client: TestClient) -> dict[str, str]:
    client.post("/api/v1/identities", json={"id": "alice", "display_label": "Alice", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "bob", "display_label": "Bob", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "eve", "display_label": "Eve", "role": "Owner/User"})
    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-a", "owner_actor_id": "alice", "credential_fingerprint": "fp-a-msg"},
    )
    sess = client.post(
        "/api/v1/sessions",
        json={"actor_id": "alice", "device_id": "dev-a", "peer_id": "bob"},
    ).json()
    return {"session_id": sess["id"]}


def test_recipient_binding_aad_tamper_replay_and_no_plaintext_logs(stage9_env) -> None:
    client, _ = stage9_env
    ctx = _seed_messaging_actors(client)
    secret_text = "CONFIDENTIAL_QSHIELD_MSG_9911"

    sent = client.post(
        "/api/v1/messages/send",
        json={
            "sender_id": "alice",
            "recipient_id": "bob",
            "session_id": ctx["session_id"],
            "plaintext": secret_text,
        },
    )
    assert sent.status_code == 201
    msg_id = sent.json()["id"]
    assert secret_text not in sent.text

    # 1. Wrong recipient fails (403) with zero plaintext
    wrong_rec = client.post(
        f"/api/v1/messages/{msg_id}/deliver",
        json={"recipient_id": "eve"},
    )
    assert wrong_rec.status_code == 403
    assert secret_text not in wrong_rec.text

    # 2. Modified AAD fails authentication (400) with zero plaintext
    tampered_aad = base64.b64encode(json.dumps({"recipient_id": "eve"}).encode("utf-8")).decode("ascii")
    bad_aad = client.post(
        f"/api/v1/messages/{msg_id}/deliver",
        json={"recipient_id": "bob", "override_aad_b64": tampered_aad},
    )
    assert bad_aad.status_code == 400
    assert secret_text not in bad_aad.text

    # 3. Intended recipient succeeds
    ok_del = client.post(
        f"/api/v1/messages/{msg_id}/deliver",
        json={"recipient_id": "bob"},
    )
    assert ok_del.status_code == 200
    assert ok_del.json()["plaintext"] == secret_text
    assert ok_del.json()["status"] == "delivered"

    # 4. Duplicate replay rejected
    replay = client.post(
        f"/api/v1/messages/{msg_id}/deliver",
        json={"recipient_id": "bob"},
    )
    assert replay.status_code == 400
    assert secret_text not in replay.text

    # 5. Plaintext never appears in audit events
    audit_export = client.get("/api/v1/audit/export").text
    assert secret_text not in audit_export


def test_loss_reordering_recovery_and_incomplete_discard(stage9_env) -> None:
    client, TestingSession = stage9_env
    ctx = _seed_messaging_actors(client)

    m1 = client.post(
        "/api/v1/messages/send",
        json={
            "sender_id": "alice",
            "recipient_id": "bob",
            "session_id": ctx["session_id"],
            "plaintext": "MSG_SEQ_1",
            "simulate_pending_recovery": True,
        },
    ).json()
    m2 = client.post(
        "/api/v1/messages/send",
        json={
            "sender_id": "alice",
            "recipient_id": "bob",
            "session_id": ctx["session_id"],
            "plaintext": "MSG_SEQ_2",
            "simulate_pending_recovery": True,
        },
    ).json()

    # Corrupt m2 to simulate an incomplete/truncated message
    with TestingSession() as db:
        row = db.get(Message, m2["id"])
        assert row is not None
        row.tag_b64 = ""
        db.commit()

    rec = client.post(
        "/api/v1/messages/recover",
        json={"session_id": ctx["session_id"], "recipient_id": "bob"},
    ).json()
    assert rec["delivered_count"] == 1
    assert rec["failed_count"] == 1
    assert m1["id"] in rec["delivered_ids"]
    assert m2["id"] in rec["failed_ids"]


def test_peer_bound_session_resumption_and_honest_forward_secrecy(stage9_env) -> None:
    client, _ = stage9_env
    ctx = _seed_messaging_actors(client)

    tok = client.post(
        "/api/v1/messages/resumption-token",
        json={"session_id": ctx["session_id"], "actor_id": "alice", "peer_id": "bob"},
    ).json()

    # Same actor & peer succeeds
    ok_res = client.post(
        "/api/v1/messages/resume",
        json={"token_bundle": tok, "actor_id": "alice", "peer_id": "bob"},
    )
    assert ok_res.status_code == 200
    assert ok_res.json()["resumed"] is True
    assert ok_res.json()["forward_secrecy"] == "NOT_ESTABLISHED"

    # Cross-peer resumption denied
    cross_peer = client.post(
        "/api/v1/messages/resume",
        json={"token_bundle": tok, "actor_id": "alice", "peer_id": "eve"},
    )
    assert cross_peer.status_code == 403

    # Cross-identity resumption denied
    cross_actor = client.post(
        "/api/v1/messages/resume",
        json={"token_bundle": tok, "actor_id": "bob", "peer_id": "bob"},
    )
    assert cross_actor.status_code == 403

    sec_status = client.get("/api/v1/messages/security-status").json()
    assert sec_status["forward_secrecy"] == "NOT_ESTABLISHED"

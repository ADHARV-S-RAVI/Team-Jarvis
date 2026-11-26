"""Stage 7 tests: append-only audit hash chain, tamper/injection detection, and receipt verification."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import sessionmaker

from backend.app.audit.service import append_audit_event, verify_audit_records
from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


@pytest.fixture()
def stage7_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage7_test.db"
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


def test_audit_chain_verify_search_timeline_export_and_receipt_link(stage7_env) -> None:
    client, _ = stage7_env

    # Perform real operations with a specific correlation ID
    headers = {"X-Correlation-ID": "corr-stage7-001"}
    client.post(
        "/api/v1/identities",
        json={"id": "alice", "display_label": "Alice", "role": "Owner/User"},
        headers=headers,
    )
    client.post(
        "/api/v1/identities",
        json={"id": "secop", "display_label": "SecOp", "role": "Security Operator"},
        headers=headers,
    )
    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-a1", "owner_actor_id": "alice", "credential_fingerprint": "fp-a1-s7"},
        headers=headers,
    )
    lost = client.post(
        "/api/v1/incidents/lost-device",
        json={
            "operator_actor_id": "secop",
            "device_id": "dev-a1",
            "reason": "Lost laptop",
            "confirmed": True,
        },
        headers=headers,
    )
    assert lost.status_code == 201
    incident_id = lost.json()["incident"]["id"]

    # Chain verifies cleanly
    ver = client.post("/api/v1/audit/verify").json()
    assert ver["valid"] is True
    assert ver["checked_events"] >= 4
    assert ver["canonical_version"] == "v1"
    assert ver["genesis"] == "GENESIS"

    # Search & event detail
    events = client.get("/api/v1/audit/events", params={"actor_id": "secop"}).json()
    assert len(events) >= 1
    ev_id = events[0]["event_id"]
    assert client.get(f"/api/v1/audit/events/{ev_id}").status_code == 200

    # Correlation timeline
    tl = client.get("/api/v1/audit/timeline/corr-stage7-001").json()
    assert len(tl) >= 4
    assert [e["sequence"] for e in tl] == sorted(e["sequence"] for e in tl)

    # Sanitized export
    exp = client.get("/api/v1/audit/export").json()
    assert exp["verification"]["valid"] is True
    assert exp["ml_dsa_checkpoint_status"] == "DEFERRED_NOT_IMPLEMENTED"

    # Non-destructive tamper demo detects actor mutation without mutating DB
    demo = client.post("/api/v1/audit/tamper-demo").json()
    assert demo["detected"] is True
    assert client.post("/api/v1/audit/verify").json()["valid"] is True

    # Proof-carrying incident receipt links to verified audit chain
    rec_ver = client.get(f"/api/v1/incidents/{incident_id}/verify").json()
    assert rec_ver["valid"] is True
    assert rec_ver["audit_event_found"] is True
    assert rec_ver["chain_valid"] is True


def test_audit_verifier_detects_all_tamper_modes_and_sanitizes_secrets(stage7_env) -> None:
    client, TestingSession = stage7_env

    with TestingSession() as db:
        e1 = append_audit_event(
            db,
            actor_id="alice",
            action="vault:read",
            target="res-1\n{\"actor\":\"admin\"}",
            decision="ALLOW",
            reason="ok\r\ninjected",
            correlation_id="c1",
            metadata={"session_token": "SUPER_SECRET_TOKEN", "plaintext": "TOP_SECRET", "note": "line1\nline2"},
        )
        append_audit_event(
            db,
            actor_id="secop",
            action="device:revoke",
            target="dev-1",
            decision="REVOKED",
            reason="lost",
            correlation_id="c2",
        )
        append_audit_event(
            db,
            actor_id="alice",
            action="vault:read",
            target="res-2",
            decision="DENY",
            reason="revoked",
            correlation_id="c3",
        )

        # Boundary injection normalized & secrets redacted
        assert "\n" not in e1.target
        assert "\r" not in e1.reason
        meta = json.loads(e1.metadata_json)
        assert meta["session_token"] == "[REDACTED]"
        assert meta["plaintext"] == "[REDACTED]"
        assert "\n" not in meta["note"]

    exported = client.get("/api/v1/audit/export").json()["events"]
    assert verify_audit_records(exported)["valid"] is True

    # 1. Event modification
    mod = copy.deepcopy(exported)
    mod[1]["reason"] = "forged-reason"
    res_mod = verify_audit_records(mod)
    assert res_mod["valid"] is False
    assert any("EVENT_HASH_MISMATCH_MODIFIED" in f["issue"] for f in res_mod["failures"])

    # 2. Actor mutation
    act = copy.deepcopy(exported)
    act[0]["actor_id"] = "admin"
    res_act = verify_audit_records(act)
    assert res_act["valid"] is False
    assert any("EVENT_HASH_MISMATCH_MODIFIED" in f["issue"] for f in res_act["failures"])

    # 3. Deletion (sequence gap)
    deleted = copy.deepcopy(exported)
    del deleted[1]
    res_del = verify_audit_records(deleted)
    assert res_del["valid"] is False
    assert any("SEQUENCE_GAP_OR_REORDER" in f["issue"] for f in res_del["failures"])

    # 4. Reordering
    reordered = [copy.deepcopy(exported[1]), copy.deepcopy(exported[0]), copy.deepcopy(exported[2])]
    res_reo = verify_audit_records(reordered)
    assert res_reo["valid"] is False
    assert any("SEQUENCE_GAP_OR_REORDER" in f["issue"] for f in res_reo["failures"])

    # 5. Raw boundary injection in stored record
    injected = copy.deepcopy(exported)
    injected[0]["target"] = "res-1\n{\"actor\":\"root\"}"
    res_inj = verify_audit_records(injected)
    assert res_inj["valid"] is False
    assert any("BOUNDARY_INJECTION_IN_TARGET" in f["issue"] for f in res_inj["failures"])

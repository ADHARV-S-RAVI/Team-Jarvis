"""Stage 6 tests: 7-point crash injection matrix, journal integrity, and backup verification."""

from __future__ import annotations

import copy
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import KeyMetadata, RotationJournal
from backend.app.db.session import create_db_engine, get_db
from backend.app.keys.service import KeyMaterialStore, get_active_key_metadata
from backend.app.main import create_app
from backend.app.recovery.service import (
    SimulatedCrashError,
    recover_rotation_journal,
    run_journaled_rotation,
)
from backend.app.services.foundation_service import DomainValidationError


@pytest.fixture()
def stage6_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage6_test.db"
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


def _seed_stage6(client: TestClient) -> dict[str, dict]:
    client.post("/api/v1/identities", json={"id": "alice", "display_label": "Alice", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "secop", "display_label": "SecOp", "role": "Security Operator"})
    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-a1", "owner_actor_id": "alice", "credential_fingerprint": "fp-a1-s6"},
    )
    s_a = client.post(
        "/api/v1/sessions",
        json={"actor_id": "alice", "device_id": "dev-a1", "peer_id": "vault"},
    ).json()
    client.post(
        "/api/v1/vault/resources",
        json={"resource_id": "res-s6", "owner_actor_id": "alice", "plaintext": "STAGE6_PROTECTED_DATA"},
    )
    return {"alice": s_a}


@pytest.mark.parametrize(
    "crash_point,expect_committed",
    [
        ("after_prepare", False),
        ("after_backup", False),
        ("after_node_partial_ack", False),
        ("before_commit", False),
        ("immediately_after_commit", True),
        ("during_retirement", True),
        ("after_revocation_tombstone", True),
    ],
)
def test_crash_injection_matrix_all_7_points(
    stage6_env, crash_point: str, expect_committed: bool
) -> None:
    client, TestingSession = stage6_env
    sessions = _seed_stage6(client)
    s_a = sessions["alice"]

    with TestingSession() as db:
        before_active = get_active_key_metadata(db).version
        op_id = None
        with pytest.raises(SimulatedCrashError) as exc_info:
            run_journaled_rotation(
                db,
                operator_actor_id="secop",
                reason=f"Crash test at {crash_point}",
                retire_policy="REVOKED",
                crash_at=crash_point,
            )
        op_id = exc_info.value.operation_id

    # Recover via API (simulating fresh process / restart)
    rec = client.post(
        f"/api/v1/keys/recover/{op_id}",
        json={"operator_actor_id": "secop"},
    )
    assert rec.status_code == 200
    rec_data = rec.json()
    assert rec_data["committed"] is expect_committed

    with TestingSession() as db:
        active_after = get_active_key_metadata(db).version
        if expect_committed:
            assert rec_data["recovery_outcome"] == "RECOVERED_POST_COMMIT"
            assert active_after > before_active
            prev_key = db.execute(
                select(KeyMetadata).where(KeyMetadata.version == before_active)
            ).scalar_one()
            assert prev_key.state == "REVOKED"
        else:
            assert rec_data["recovery_outcome"] == "RECOVERED_PRE_COMMIT"
            assert active_after == before_active

    # Duplicate recovery must be idempotent
    dup_rec = client.post(
        f"/api/v1/keys/recover/{op_id}",
        json={"operator_actor_id": "secop"},
    )
    assert dup_rec.status_code == 200
    assert dup_rec.json()["recovery_outcome"] == "IDEMPOTENT_ALREADY_RECOVERED"

    # Pre-commit recovery preserves authorized vault access; post-commit with REVOKED denies old key
    read_resp = client.post(
        "/api/v1/vault/resources/res-s6/read",
        json={
            "actor_id": "alice",
            "session_id": s_a["id"],
            "session_token": s_a["session_token"],
            "device_id": "dev-a1",
            "peer_id": "vault",
        },
    )
    if expect_committed:
        assert read_resp.status_code == 403
    else:
        assert read_resp.status_code == 200
        assert read_resp.json()["plaintext"] == "STAGE6_PROTECTED_DATA"


def test_corrupted_journal_and_pre_commit_revocation_fail_closed(stage6_env) -> None:
    client, TestingSession = stage6_env
    _seed_stage6(client)

    with TestingSession() as db:
        with pytest.raises(SimulatedCrashError) as exc_info:
            run_journaled_rotation(
                db,
                operator_actor_id="secop",
                reason="Tamper test",
                crash_at="before_commit",
            )
        op_id = exc_info.value.operation_id

        # Tamper with journal phase without updating integrity_hash
        journal = db.get(RotationJournal, op_id)
        assert journal is not None
        journal.committed = True
        db.commit()

        with pytest.raises(DomainValidationError, match="integrity hash mismatch"):
            recover_rotation_journal(db, operation_id=op_id, operator_actor_id="secop")


def test_backup_create_verify_restore_and_negative_cases(stage6_env, tmp_path: Path) -> None:
    client, TestingSession = stage6_env
    _seed_stage6(client)

    # Create valid backup
    b_resp = client.post("/api/v1/keys/backups/create", json={"operator_actor_id": "secop"})
    assert b_resp.status_code == 201
    manifest = b_resp.json()

    # Valid verify & idempotent restore
    v_ok = client.post("/api/v1/keys/backups/verify", json={"manifest": manifest})
    assert v_ok.status_code == 200 and v_ok.json()["valid"] is True

    r_ok = client.post(
        "/api/v1/keys/backups/restore",
        json={"operator_actor_id": "secop", "manifest": manifest},
    )
    assert r_ok.status_code == 200 and r_ok.json()["status"] == "RESTORED"
    r_dup = client.post(
        "/api/v1/keys/backups/restore",
        json={"operator_actor_id": "secop", "manifest": manifest},
    )
    assert r_dup.status_code == 200

    # 1. Incomplete backup rejected
    incomplete = copy.deepcopy(manifest)
    del incomplete["hmac_hex"]
    v_inc = client.post("/api/v1/keys/backups/verify", json={"manifest": incomplete})
    assert v_inc.json() == {"valid": False, "reason": "BACKUP_INCOMPLETE"}

    # 2. Byte-tampered payload rejected
    tampered = copy.deepcopy(manifest)
    tampered["payload"]["active_key_version"] = 99
    v_tam = client.post("/api/v1/keys/backups/verify", json={"manifest": tampered})
    assert v_tam.json() == {"valid": False, "reason": "BACKUP_TAMPERED_DIGEST"}

    # 3. Wrong-key / invalid HMAC rejected
    wrong_hmac = copy.deepcopy(manifest)
    wrong_hmac["hmac_hex"] = "0" * 64
    v_hm = client.post("/api/v1/keys/backups/verify", json={"manifest": wrong_hmac})
    assert v_hm.json() == {"valid": False, "reason": "BACKUP_INVALID_HMAC_OR_WRONG_KEY"}

    # 4. Stale backup rejected after a newer key rotation/revocation
    rot = client.post(
        "/api/v1/keys/rotate",
        json={"operator_actor_id": "secop", "reason": "Advance epoch", "retire_policy": "REVOKED"},
    )
    assert rot.status_code == 200

    v_stale = client.post("/api/v1/keys/backups/verify", json={"manifest": manifest})
    assert v_stale.json()["valid"] is False
    assert "STALE" in v_stale.json()["reason"]

    r_stale = client.post(
        "/api/v1/keys/backups/restore",
        json={"operator_actor_id": "secop", "manifest": manifest},
    )
    assert r_stale.status_code == 400

    # Unauthorized non-operator cannot restore backup
    unauth = client.post(
        "/api/v1/keys/backups/restore",
        json={"operator_actor_id": "alice", "manifest": manifest},
    )
    assert unauth.status_code == 403

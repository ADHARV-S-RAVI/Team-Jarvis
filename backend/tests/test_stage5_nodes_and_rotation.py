"""Stage 5 tests: 3-7 simulated nodes, monotonic revocation, convergence, key rotation, and races."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import sessionmaker

from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app
from backend.app.nodes.service import (
    node_check_access,
    propagate_revocation_to_nodes,
)


@pytest.fixture()
def stage5_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage5_test.db"
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
        yield client, TestingSession, engine
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        get_settings.cache_clear()


def _seed_stage5(client: TestClient) -> dict[str, dict]:
    client.post("/api/v1/identities", json={"id": "alice", "display_label": "Alice", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "bob", "display_label": "Bob", "role": "Owner/User"})
    client.post("/api/v1/identities", json={"id": "secop", "display_label": "SecOp", "role": "Security Operator"})

    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-a1", "owner_actor_id": "alice", "credential_fingerprint": "fp-a1-0001"},
    )
    client.post(
        "/api/v1/devices/enroll",
        json={"id": "dev-b1", "owner_actor_id": "bob", "credential_fingerprint": "fp-b1-0001"},
    )

    s_a = client.post(
        "/api/v1/sessions",
        json={"actor_id": "alice", "device_id": "dev-a1", "peer_id": "vault"},
    ).json()
    s_b = client.post(
        "/api/v1/sessions",
        json={"actor_id": "bob", "device_id": "dev-b1", "peer_id": "vault"},
    ).json()

    client.post(
        "/api/v1/vault/resources",
        json={"resource_id": "res-v1", "owner_actor_id": "alice", "plaintext": "V1_SECRET_DATA"},
    )
    return {"alice": s_a, "bob": s_b}


def test_node_simulator_configuration_3_to_7_and_partition_recovery(stage5_env) -> None:
    client, TestingSession, _ = stage5_env
    _seed_stage5(client)

    # Default 3 nodes, configurable up to 7, rejects <3 or >7
    assert len(client.get("/api/v1/nodes").json()) == 3
    assert client.post("/api/v1/nodes/configure", json={"count": 5}).status_code == 200
    assert len(client.get("/api/v1/nodes").json()) == 5
    assert client.post("/api/v1/nodes/configure", json={"count": 2}).status_code == 422
    assert client.post("/api/v1/nodes/configure", json={"count": 8}).status_code == 422

    # Partition sim-node-2, then trigger lost-device propagation
    assert client.post("/api/v1/nodes/sim-node-2/partition").status_code == 200
    lost = client.post(
        "/api/v1/incidents/lost-device",
        json={
            "operator_actor_id": "secop",
            "device_id": "dev-a1",
            "reason": "Lost on train",
            "confirmed": True,
        },
    )
    assert lost.status_code == 201
    receipt = lost.json()["receipt"]
    acks_payload = json.loads(receipt["node_acks_json"])
    assert acks_payload["status"] == "NOT_CONVERGED"
    assert acks_payload["converged_nodes"] == 4
    assert acks_payload["total_nodes"] == 5
    assert receipt["convergence_ms"] is None

    # Partitioned node fails closed; reachable node denies revoked device
    with TestingSession() as db:
        ok_p, reason_p = node_check_access(
            db, node_id="sim-node-2", actor_id="alice", device_id="dev-a1", key_version=1
        )
        assert ok_p is False and reason_p == "NODE_PARTITIONED_FAIL_CLOSED"

        ok_r, reason_r = node_check_access(
            db, node_id="sim-node-1", actor_id="alice", device_id="dev-a1", key_version=1
        )
        assert ok_r is False and reason_r == "NODE_DEVICE_REVOKED"

        # Idempotent duplicate & stale epoch rejection
        dup = propagate_revocation_to_nodes(db, subject_type="device", subject_id="dev-a1", epoch=1)
        assert any(a["result"] == "IDEMPOTENT_ACK" for a in dup["acks"])
        stale = propagate_revocation_to_nodes(db, subject_type="device", subject_id="dev-a1", epoch=0)
        assert any(a["result"] == "STALE_IGNORED" for a in stale["acks"])

    # Recover sim-node-2 and reconcile -> CONVERGED
    assert client.post("/api/v1/nodes/sim-node-2/recover").status_code == 200
    rec = client.post("/api/v1/nodes/reconcile").json()
    assert rec["status"] == "CONVERGED"
    assert rec["converged_nodes"] == 5

    with TestingSession() as db:
        ok_after, reason_after = node_check_access(
            db, node_id="sim-node-2", actor_id="alice", device_id="dev-a1", key_version=1
        )
        assert ok_after is False and reason_after == "NODE_DEVICE_REVOKED"

    # Convergence metrics are measured from actual NodeAcknowledgements
    metrics = client.get("/api/v1/nodes/metrics").json()
    assert metrics["sample_count"] > 0
    assert metrics["p50_ms"] is not None
    assert metrics["max_ms"] >= metrics["p50_ms"]


def test_key_rotation_cutoff_in_flight_and_partition_abort(stage5_env) -> None:
    client, TestingSession, _ = stage5_env
    sessions = _seed_stage5(client)
    s_a = sessions["alice"]

    # Partition a node -> rotation aborts safely before commit
    assert client.post("/api/v1/nodes/sim-node-3/partition").status_code == 200
    aborted = client.post(
        "/api/v1/keys/rotate",
        json={"operator_actor_id": "secop", "reason": "Scheduled rotation", "retire_policy": "RETIRED"},
    )
    assert aborted.status_code == 400

    # Recover node -> rotation succeeds (v1 -> v2)
    client.post("/api/v1/nodes/sim-node-3/recover")
    rot = client.post(
        "/api/v1/keys/rotate",
        json={"operator_actor_id": "secop", "reason": "Scheduled rotation", "retire_policy": "RETIRED"},
    )
    assert rot.status_code == 200
    rot_data = rot.json()
    assert rot_data["previous_version"] == 1
    new_version = rot_data["new_version"]
    assert new_version >= 2
    assert rot_data["committed"] is True
    assert rot_data["node_status"] == "CONVERGED"

    # New encryption automatically uses new active version
    store_v2 = client.post(
        "/api/v1/vault/resources",
        json={"resource_id": "res-v2", "owner_actor_id": "alice", "plaintext": "V2_SECRET_DATA"},
    )
    assert store_v2.status_code == 201
    assert store_v2.json()["key_version"] == new_version

    # New read of v1 fails after zero-grace cutoff; explicit in_flight=True succeeds during migration
    cutoff_deny = client.post(
        "/api/v1/vault/resources/res-v1/read",
        json={
            "actor_id": "alice",
            "session_id": s_a["id"],
            "session_token": s_a["session_token"],
            "device_id": "dev-a1",
            "peer_id": "vault",
            "in_flight": False,
        },
    )
    assert cutoff_deny.status_code == 403

    inflight_ok = client.post(
        "/api/v1/vault/resources/res-v1/read",
        json={
            "actor_id": "alice",
            "session_id": s_a["id"],
            "session_token": s_a["session_token"],
            "device_id": "dev-a1",
            "peer_id": "vault",
            "in_flight": True,
        },
    )
    assert inflight_ok.status_code == 200
    assert inflight_ok.json()["plaintext"] == "V1_SECRET_DATA"

    # Compromise new key -> terminal COMPROMISED denies even with in_flight=True
    comp = client.post(
        f"/api/v1/keys/key-v{new_version}/compromise",
        json={"operator_actor_id": "secop", "reason": "Key material exposure"},
    )
    assert comp.status_code == 200
    assert comp.json()["state"] == "COMPROMISED"

    comp_read = client.post(
        "/api/v1/vault/resources/res-v2/read",
        json={
            "actor_id": "alice",
            "session_id": s_a["id"],
            "session_token": s_a["session_token"],
            "device_id": "dev-a1",
            "peer_id": "vault",
            "in_flight": True,
        },
    )
    assert comp_read.status_code == 403


def test_concurrent_read_vs_revoke_race(stage5_env) -> None:
    client, _, _ = stage5_env
    sessions = _seed_stage5(client)
    s_a = sessions["alice"]

    def do_read() -> int:
        r = client.post(
            "/api/v1/vault/resources/res-v1/read",
            json={
                "actor_id": "alice",
                "session_id": s_a["id"],
                "session_token": s_a["session_token"],
                "device_id": "dev-a1",
                "peer_id": "vault",
            },
        )
        return r.status_code

    def do_revoke() -> int:
        r = client.post(
            "/api/v1/incidents/lost-device",
            json={
                "operator_actor_id": "secop",
                "device_id": "dev-a1",
                "reason": "Concurrent revoke",
                "confirmed": True,
            },
        )
        return r.status_code

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_rev = pool.submit(do_revoke)
        f_reads = [pool.submit(do_read) for _ in range(3)]
        assert f_rev.result() == 201
        for f in f_reads:
            assert f.result() in {200, 403}

    # Post-revoke read MUST always be 403
    assert do_read() == 403

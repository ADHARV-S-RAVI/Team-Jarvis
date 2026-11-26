"""Stage 8 tests: deterministic privilege/lateral-movement detection, clock skew, and practice dataset metrics."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import DetectorEvent
from backend.app.db.session import create_db_engine, get_db
from backend.app.detector.service import generate_synthetic_events, parse_events_csv
from backend.app.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
PRACTICE_DIR = REPO_ROOT / "tools" / "Track-4-Toolkit" / "practice"


@pytest.fixture()
def stage8_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "stage8_test.db"
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


def test_official_practice_dataset_evaluation_and_clock_skew(stage8_env) -> None:
    client, TestingSession = stage8_env

    events_csv = (PRACTICE_DIR / "events.csv").read_text(encoding="utf-8")
    approvals_data = json.loads((PRACTICE_DIR / "approvals.json").read_text(encoding="utf-8"))
    labels: dict[str, str] = {}
    with (PRACTICE_DIR / "labels.csv").open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            labels[row["event_id"]] = row["label"]

    parsed_events = [dict(row) for row in csv.DictReader(io.StringIO(events_csv))]
    ingest_res = client.post(
        "/api/v1/detector/ingest",
        json={"events": parsed_events, "reorder_window_ms": 5000, "clock_uncertainty_ms": 500},
    )
    assert ingest_res.status_code == 200
    ingest_json = ingest_res.json()
    assert ingest_json["ingested_count"] == 22
    # evt-013 arrives after evt-014
    assert ingest_json["out_of_order_count"] == 1

    with TestingSession() as db:
        evt13 = db.get(DetectorEvent, "evt-013")
        assert evt13 is not None and evt13.out_of_order is True

    alerts_resp = client.post(
        "/api/v1/detector/run",
        json={"approvals": approvals_data["changes"]},
    )
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    rule_ids = {a["rule_id"] for a in alerts}
    assert "RULE_PRIV_SELF_ESCALATION" in rule_ids
    assert "RULE_PRIV_SENSITIVE_AFTER_CHANGE" in rule_ids
    assert "RULE_LATERAL_MULTI_HOP" in rule_ids

    # Evaluate actual metrics against practice/labels.csv
    metrics_resp = client.post(
        "/api/v1/detector/metrics",
        json={"labels": labels, "dataset_version": "practice-v1"},
    )
    assert metrics_resp.status_code == 200
    m = metrics_resp.json()
    assert m["status"] == "EVALUATED"
    assert m["tp"] == 5  # evt-008, evt-009, evt-010, evt-011, evt-012
    assert m["fp"] == 0
    assert m["fn"] == 0
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1"] == 1.0

    # Without labels -> NOT_EVALUATED
    no_labels = client.post("/api/v1/detector/metrics", json={}).json()
    assert no_labels["status"] == "NOT_EVALUATED"


def test_revoked_actor_attempt_clock_uncertainty_and_malformed_input(stage8_env) -> None:
    client, TestingSession = stage8_env

    # Create and revoke an actor in Q-SHIELD DB
    client.post("/api/v1/identities", json={"id": "rev-user", "display_label": "Rev", "role": "Owner/User"})
    client.post(
        "/api/v1/revocations",
        json={"subject_type": "actor", "subject_id": "rev-user", "reason": "Compromised"},
    )

    # Events with overlapping timestamps (within 500ms uncertainty) + unknown extra field
    events = [
        {
            "event_id": "e-rev-1",
            "event_time_utc": "2026-02-01T12:00:00.000Z",
            "actor": "rev-user",
            "source_service": "portal",
            "target_service": "vault",
            "action": "read",
            "unknown_extra_field": "preserved_safely",
        },
        {
            "event_id": "e-rev-2",
            "event_time_utc": "2026-02-01T12:00:00.200Z",
            "actor": "rev-user",
            "source_service": "vault",
            "target_service": "billing",
            "action": "read",
        },
    ]
    ing = client.post(
        "/api/v1/detector/ingest",
        json={"events": events, "clock_uncertainty_ms": 500},
    )
    assert ing.status_code == 200
    assert ing.json()["order_uncertain_count"] == 1

    with TestingSession() as db:
        e2 = db.get(DetectorEvent, "e-rev-2")
        assert e2 is not None and e2.order_uncertain is True

    alerts = client.post("/api/v1/detector/run", json={"approvals": []}).json()
    assert any(a["rule_id"] == "RULE_PRIV_REVOKED_ACTOR_ATTEMPT" for a in alerts)

    # Malformed event fails safely with 400
    bad = client.post("/api/v1/detector/ingest", json={"events": [{"actor": "x"}]})
    assert bad.status_code == 400


def test_seeded_synthetic_generator_and_rules_endpoint(stage8_env) -> None:
    client, _ = stage8_env
    ev1, lbl1 = generate_synthetic_events(seed=99, count=10)
    ev2, lbl2 = generate_synthetic_events(seed=99, count=10)
    assert ev1 == ev2 and lbl1 == lbl2

    rules = client.get("/api/v1/detector/rules").json()
    assert len(rules) >= 5

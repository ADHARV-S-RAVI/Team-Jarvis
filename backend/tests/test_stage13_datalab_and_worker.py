"""Tests for Data Verification Lab, streaming algorithms, 24/7 worker, and system health."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import io
from pathlib import Path
import zipfile

from alembic import command
from alembic.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import sessionmaker

from backend.app.datalab.algorithms import compute_merkle_root
from backend.app.datalab.worker import DurableBackgroundWorker
from backend.app.db.models import BackgroundJob
from backend.app.db.session import create_db_engine, get_db
from backend.app.main import create_app


@pytest.fixture()
def datalab_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_file = tmp_path / "datalab_test.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("QSHIELD_KEY_STORE_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("QSHIELD_UPLOAD_DIR", str(tmp_path / "uploads"))

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
        yield client, TestingSession, tmp_path
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
        get_settings.cache_clear()


def test_resumable_chunked_csv_upload_merkle_and_welford_profile(datalab_env) -> None:
    client, _Sess, _tmp = datalab_env
    csv_bytes = (
        b"actor,score,latency_ms\n"
        b"alice,10,12.5\n"
        b"bob,20,15.5\n"
        b"alice,10,12.5\n"
        b"secop,,18.0\n"
    )
    # 3 chunks (uneven leaf count -> tests odd Merkle tree promotion)
    chunk_size = 1024
    # Force 3 chunks by sending declared_size_bytes with chunk_size=30
    chunk_size = 30
    full_sha = hashlib.sha256(csv_bytes).hexdigest()

    init_res = client.post(
        "/api/v1/datalab/uploads/init",
        json={
            "filename": "../../evil_path/metrics.csv",
            "declared_size_bytes": len(csv_bytes),
            "chunk_size_bytes": 1024,
            "reference_sha256": full_sha,
        },
    )
    assert init_res.status_code == 201
    up = init_res.json()
    assert up["filename"] == "metrics.csv"  # path traversal stripped
    upload_id = up["upload_id"]

    # Corrupt chunk test rejected
    bad = client.put(
        f"/api/v1/datalab/uploads/{upload_id}/chunks/0",
        content=csv_bytes,
        headers={"X-Chunk-SHA256": "0" * 64},
    )
    assert bad.status_code == 400

    # Pause -> Resume -> Valid upload
    assert client.post(f"/api/v1/datalab/uploads/{upload_id}/pause").json()["status"] == "PAUSED"
    assert client.post(f"/api/v1/datalab/uploads/{upload_id}/resume").json()["status"] == "UPLOADING"

    good = client.put(
        f"/api/v1/datalab/uploads/{upload_id}/chunks/0",
        content=csv_bytes,
        headers={"X-Chunk-SHA256": full_sha},
    )
    assert good.status_code == 200

    fin = client.post(f"/api/v1/datalab/uploads/{upload_id}/finalize?inline=true")
    assert fin.status_code == 200
    fjson = fin.json()
    assert fjson["sha256"] == full_sha
    assert fjson["verification_status"] == "PASSED"

    detail = client.get(f"/api/v1/datalab/files/{fjson['file_id']}").json()
    assert detail["reference_status"] == "MATCH"
    assert detail["dataset_profile"]["row_count"] == 4
    assert detail["dataset_profile"]["duplicate_rows"] == 1
    assert detail["dataset_profile"]["missing_cells"] == 1
    assert detail["dataset_profile"]["numeric_stats"]["score"]["mean"] == 13.3333
    assert len(detail["stages"]) == 14

    # Reference mismatch flips to FAILED / CRITICAL
    mm = client.post(
        f"/api/v1/datalab/files/{fjson['file_id']}/verify-reference",
        json={"reference_sha256": "a" * 64},
    ).json()
    assert mm["reference_status"] == "MISMATCH"
    assert mm["verification_status"] == "FAILED"


def test_merkle_tree_uneven_chunks() -> None:
    h1 = hashlib.sha256(b"c1").hexdigest()
    h2 = hashlib.sha256(b"c2").hexdigest()
    h3 = hashlib.sha256(b"c3").hexdigest()
    root = compute_merkle_root([h1, h2, h3])
    assert root is not None and len(root) == 64
    assert compute_merkle_root([]) is None


def test_archive_traversal_and_x509_cert_analysis(datalab_env) -> None:
    client, _Sess, _tmp = datalab_env

    # 1. ZIP with path traversal entry
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("../escape.txt", b"bad")
    zbytes = zbuf.getvalue()
    u1 = client.post(
        "/api/v1/datalab/uploads/init",
        json={"filename": "bundle.zip", "declared_size_bytes": len(zbytes), "chunk_size_bytes": 1024},
    ).json()["upload_id"]
    client.put(f"/api/v1/datalab/uploads/{u1}/chunks/0", content=zbytes)
    f1 = client.post(f"/api/v1/datalab/uploads/{u1}/finalize?inline=true").json()
    d1 = client.get(f"/api/v1/datalab/files/{f1['file_id']}").json()
    assert d1["detected_category"] == "archive"
    assert d1["risk_level"] == "CRITICAL"
    assert any(x["code"] == "PATH_TRAVERSAL_ENTRY" for x in d1["findings"])

    # 2. Self-signed X.509 PEM certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qshield.local")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
    u2 = client.post(
        "/api/v1/datalab/uploads/init",
        json={"filename": "test.pem", "declared_size_bytes": len(pem_bytes), "chunk_size_bytes": 4096},
    ).json()["upload_id"]
    client.put(f"/api/v1/datalab/uploads/{u2}/chunks/0", content=pem_bytes)
    f2 = client.post(f"/api/v1/datalab/uploads/{u2}/finalize?inline=true").json()
    d2 = client.get(f"/api/v1/datalab/files/{f2['file_id']}").json()
    assert d2["detected_category"] == "certificate"
    assert d2["crypto_readiness"] == "Classical cryptography detected"
    assert d2["signature_status"] == "PARSED_VALID_DATES_UNTRUSTED_ROOT"


def test_worker_restart_recovery_and_system_metrics(datalab_env) -> None:
    client, TestingSession, _tmp = datalab_env
    with TestingSession() as db:
        stuck = BackgroundJob(job_type="NOOP", target_id="t1", status="RUNNING", attempts=0, max_attempts=3)
        db.add(stuck)
        db.commit()
        jid = stuck.id

    worker = DurableBackgroundWorker()
    worker._session_factory = TestingSession
    worker._recover_interrupted_jobs()

    with TestingSession() as db:
        rec = db.get(BackgroundJob, jid)
        assert rec is not None and rec.status == "QUEUED"
        assert worker._process_next_job(db) is True
        db.refresh(rec)
        assert rec.status == "COMPLETED"

    assert client.get("/api/v1/health/live").status_code == 200
    assert client.get("/api/v1/health/ready").status_code == 200
    metrics = client.get("/api/v1/system/metrics").json()
    assert "cpu_percent" in metrics and "process_rss_mb" in metrics

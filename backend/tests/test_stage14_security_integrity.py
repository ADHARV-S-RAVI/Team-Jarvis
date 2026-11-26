"""Comprehensive tests for Stage 13 Identity Assurance (WebAuthn) and File Integrity Intelligence."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import struct

from alembic import command
from alembic.config import Config
import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from backend.app.db.models import (
    IdentityCredential,
    IntegrityManifest,
    IntegrityManifestEntry,
    WebAuthnChallenge,
)
from backend.app.db.session import create_db_engine, get_db
from backend.app.identity_assurance.service import clear_rate_limit_for_test
from backend.app.integrity.service import initialize_baseline, run_application_scan
from backend.app.main import create_app


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode((s + "=" * (-len(s) % 4)).encode("ascii"))


def _synthetic_webauthn_create(challenge_b64u: str, rp_id: str = "localhost", origin: str = "http://localhost:5173"):
    """Build a cryptographically valid WebAuthn P-256 registration credential (synthetic test fixture)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    x_bytes = nums.x.to_bytes(32, "big")
    y_bytes = nums.y.to_bytes(32, "big")
    cose_key = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x_bytes, -3: y_bytes})

    cred_id = b"syn-cred-0001-stage13"
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    flags = 0x45  # UP (0x01) + UV (0x04) + AT (0x40)
    aaguid = b"\x00" * 16
    attested = aaguid + struct.pack(">H", len(cred_id)) + cred_id + cose_key
    auth_data = rp_hash + bytes([flags]) + struct.pack(">I", 1) + attested
    att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
    client_data = json.dumps({"type": "webauthn.create", "challenge": challenge_b64u, "origin": origin}).encode("utf-8")

    return priv, {
        "id": _b64u(cred_id),
        "rawId": _b64u(cred_id),
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(client_data),
            "attestationObject": _b64u(att_obj),
        },
    }


def _synthetic_webauthn_get(
    priv: ec.EllipticCurvePrivateKey,
    cred_id_b64u: str,
    challenge_b64u: str,
    *,
    sign_count: int = 2,
    rp_id: str = "localhost",
    origin: str = "http://localhost:5173",
    corrupt_sig: bool = False,
):
    rp_hash = hashlib.sha256(rp_id.encode("utf-8")).digest()
    auth_data = rp_hash + bytes([0x05]) + struct.pack(">I", sign_count)  # UP + UV
    client_data = json.dumps({"type": "webauthn.get", "challenge": challenge_b64u, "origin": origin}).encode("utf-8")
    signed_payload = auth_data + hashlib.sha256(client_data).digest()
    sig = priv.sign(signed_payload, ec.ECDSA(hashes.SHA256()))
    if corrupt_sig:
        sig = bytes([sig[0] ^ 0xFF]) + sig[1:]
    return {
        "id": cred_id_b64u,
        "rawId": cred_id_b64u,
        "type": "public-key",
        "response": {
            "clientDataJSON": _b64u(client_data),
            "authenticatorData": _b64u(auth_data),
            "signature": _b64u(sig),
        },
    }


@pytest.fixture()
def stage13_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    clear_rate_limit_for_test()
    db_file = tmp_path / "stage13.db"
    db_url = f"sqlite:///{db_file}"
    monkeypatch.setenv("QSHIELD_KEY_STORE_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("QSHIELD_ENABLE_DEV_DEMO_AUTH", "true")

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
    client.post("/api/v1/simulation/reset")
    try:
        yield client, TestingSession, tmp_path
    finally:
        clear_rate_limit_for_test()
        app.dependency_overrides.clear()
        engine.dispose()
        get_settings.cache_clear()


def test_webauthn_lifecycle_security_policy_and_device_revocation(stage13_env) -> None:
    client, TestingSession, _tmp = stage13_env

    # 1. Registration with invalid challenge rejected
    opts = client.post("/api/v1/identity-assurance/register/options", json={"actor_id": "alice"}).json()
    priv, cred_payload = _synthetic_webauthn_create(opts["options"]["challenge"])

    bad_reg = client.post(
        "/api/v1/identity-assurance/register/verify",
        json={"actor_id": "alice", "challenge_id": "wrong-id", "credential": cred_payload, "device_id": "dev-alice-01"},
    )
    assert bad_reg.status_code in (400, 403)

    # Valid registration binds to dev-alice-01 & stores no private key
    reg_res = client.post(
        "/api/v1/identity-assurance/register/verify",
        json={"actor_id": "alice", "challenge_id": opts["challenge_id"], "credential": cred_payload, "device_id": "dev-alice-01"},
    )
    assert reg_res.status_code == 201
    assert reg_res.json()["status"] == "IDENTITY CREDENTIAL REGISTERED"
    cred_db_id = reg_res.json()["id"]
    cred_id_b64 = reg_res.json()["credential_id"]

    # Replay registration challenge fails
    replay_reg = client.post(
        "/api/v1/identity-assurance/register/verify",
        json={"actor_id": "alice", "challenge_id": opts["challenge_id"], "credential": cred_payload},
    )
    assert replay_reg.status_code == 400

    # 2. Authenticate + negative checks (wrong RP, wrong origin, bad sig, expired challenge)
    a_opts = client.post("/api/v1/identity-assurance/authenticate/options", json={"actor_id": "alice"}).json()
    bad_sig_payload = _synthetic_webauthn_get(priv, cred_id_b64, a_opts["options"]["challenge"], corrupt_sig=True)
    assert client.post(
        "/api/v1/identity-assurance/authenticate/verify",
        json={"actor_id": "alice", "challenge_id": a_opts["challenge_id"], "credential": bad_sig_payload},
    ).status_code == 403

    # Wrong origin / RP ID rejected
    a_opts2 = client.post("/api/v1/identity-assurance/authenticate/options", json={"actor_id": "alice"}).json()
    good_assert = _synthetic_webauthn_get(priv, cred_id_b64, a_opts2["options"]["challenge"], sign_count=2)
    assert client.post(
        "/api/v1/identity-assurance/authenticate/verify",
        json={"actor_id": "alice", "challenge_id": a_opts2["challenge_id"], "credential": good_assert, "origin": "https://evil.example"},
    ).status_code == 400

    # Valid authentication grants WEBAUTHN_ELEVATED
    ok_auth = client.post(
        "/api/v1/identity-assurance/authenticate/verify",
        json={"actor_id": "alice", "challenge_id": a_opts2["challenge_id"], "credential": good_assert},
    )
    assert ok_auth.status_code == 200
    assert ok_auth.json()["assurance_level"] == "WEBAUTHN_ELEVATED"

    # Reused challenge fails
    assert client.post(
        "/api/v1/identity-assurance/authenticate/verify",
        json={"actor_id": "alice", "challenge_id": a_opts2["challenge_id"], "credential": good_assert},
    ).status_code == 403

    # Expired challenge fails
    a_opts3 = client.post("/api/v1/identity-assurance/authenticate/options", json={"actor_id": "alice"}).json()
    with TestingSession() as db:
        ch = db.get(WebAuthnChallenge, a_opts3["challenge_id"])
        ch.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        db.commit()
    assert client.post(
        "/api/v1/identity-assurance/authenticate/verify",
        json={"actor_id": "alice", "challenge_id": a_opts3["challenge_id"], "credential": _synthetic_webauthn_get(priv, cred_id_b64, a_opts3["options"]["challenge"], sign_count=3)},
    ).status_code == 403

    # 3. Policy enforcement + freshness expiration in 9-step authz
    login = client.post("/api/v1/auth/demo-login", json={"actor_id": "bob", "device_id": "dev-bob-01", "peer_id": "alice"}).json()
    # Non-operator cannot change policy
    assert client.put("/api/v1/identity-assurance/policy", json={"operator_actor_id": "alice", "policy_mode": "REQUIRED_FOR_SENSITIVE_ACTIONS", "freshness_window_seconds": 300}).status_code == 403
    # Operator sets REQUIRED_FOR_SENSITIVE_ACTIONS
    assert client.put("/api/v1/identity-assurance/policy", json={"operator_actor_id": "secop", "policy_mode": "REQUIRED_FOR_SENSITIVE_ACTIONS", "freshness_window_seconds": 300}).status_code == 200
    # Bob lacks fresh WebAuthn -> vault read denied with IDENTITY_ASSURANCE_REQUIRED
    deny_res = client.post("/api/v1/policy/evaluate", json={"actor_id": "bob", "session_id": login["id"], "device_id": "dev-bob-01", "resource_id": "vault-brief-bob", "action": "resource:read", "session_token": login["session_token"]}).json()
    assert deny_res["decision"] == "DENY"
    assert deny_res["reason_code"] == "IDENTITY_ASSURANCE_REQUIRED"

    # Admin recovery restores elevated assurance cleanly
    assert client.post("/api/v1/identity-assurance/recovery", json={"operator_actor_id": "secop", "target_actor_id": "bob", "reason": "Hardware key lost"}).status_code == 200
    allow_res = client.post("/api/v1/policy/evaluate", json={"actor_id": "bob", "session_id": login["id"], "device_id": "dev-bob-01", "resource_id": "vault-brief-bob", "action": "resource:read", "session_token": login["session_token"]}).json()
    assert allow_res["decision"] == "ALLOW"

    # 4. Revoking device invalidates bound credential
    assert client.post("/api/v1/devices/dev-alice-01/revoke", json={"operator_actor_id": "secop", "reason": "Lost phone"}).status_code == 200
    with TestingSession() as db:
        cred_row = db.get(IdentityCredential, cred_db_id)
        assert cred_row is not None and cred_row.credential_status == "REVOKED"

    # Camera demo logs start/stop without image data
    assert client.post("/api/v1/identity-assurance/camera-demo/event", json={"actor_id": "alice", "state": "STARTED"}).status_code == 200
    assert client.post("/api/v1/identity-assurance/camera-demo/event", json={"actor_id": "alice", "state": "STOPPED"}).status_code == 200


def test_file_integrity_baseline_tamper_detection_and_governance(stage13_env) -> None:
    client, TestingSession, tmp_path = stage13_env
    app_dir = tmp_path / "app_scope"
    app_dir.mkdir()
    (app_dir / "core.py").write_text("print('trusted')", encoding="utf-8")
    (app_dir / "keep.py").write_text("x = 1", encoding="utf-8")
    (app_dir / "ignored.pyc").write_bytes(b"\x00\x01")  # excluded

    with TestingSession() as db:
        manifest = initialize_baseline(db, operator_actor_id="secop", app_root=app_dir)
        assert manifest.status == "ACTIVE"

        # Clean scan
        clean = run_application_scan(db, actor_id="secop", app_root=app_dir)
        assert clean.files_verified == 2
        assert clean.files_modified == 0
        assert clean.files_excluded >= 1

        # Mutate one, delete one, add unexpected one
        (app_dir / "core.py").write_text("print('MODIFIED')", encoding="utf-8")
        (app_dir / "keep.py").unlink()
        (app_dir / "rogue.py").write_text("x = 999", encoding="utf-8")

        dirty = run_application_scan(db, actor_id="secop", app_root=app_dir)
        assert dirty.files_modified == 1
        assert dirty.files_missing == 1
        assert dirty.files_unexpected == 1

    # Detector picks up integrity findings deterministically
    alerts = client.post("/api/v1/detector/run", json={"approvals": []}).json()
    rids = {a["rule_id"] for a in alerts}
    assert "RULE_INTEGRITY_MODIFIED_FILE" in rids
    assert "RULE_INTEGRITY_MISSING_FILE" in rids
    assert "RULE_INTEGRITY_UNEXPECTED_FILE" in rids

    # Baseline change request governance (unauthorized approve fails; operator approve succeeds)
    creq = client.post(
        "/api/v1/integrity/baseline/change-requests",
        json={"requested_by": "alice", "reason": "Planned patch", "scan_id": dirty.id},
    ).json()
    assert client.post(
        f"/api/v1/integrity/baseline/change-requests/{creq['id']}/approve",
        json={"operator_actor_id": "alice"},
    ).status_code == 403
    assert client.post(
        f"/api/v1/integrity/baseline/change-requests/{creq['id']}/reject",
        json={"operator_actor_id": "secop"},
    ).json()["status"] == "REJECTED"

    # User-selected browser metadata scan (no file contents uploaded)
    u_scan = client.post(
        "/api/v1/integrity/scans/user-selected",
        json={
            "actor_id": "alice",
            "entries": [
                {"relative_path": "doc.txt", "sha256_hash": "a" * 64, "expected_hash": "a" * 64, "file_size": 10},
                {"relative_path": "../bad.txt", "sha256_hash": "b" * 64, "file_size": 10},
            ],
        },
    )
    assert u_scan.status_code == 400  # traversal rejected!

    u_ok = client.post(
        "/api/v1/integrity/scans/user-selected",
        json={
            "actor_id": "alice",
            "entries": [{"relative_path": "doc.txt", "sha256_hash": "a" * 64, "expected_hash": "a" * 64, "file_size": 10}],
        },
    )
    assert u_ok.status_code == 201 and u_ok.json()["files_verified"] == 1

    # Tampering manifest directly in DB is caught by verify_manifest_integrity
    with TestingSession() as db:
        ent = db.execute(select(IntegrityManifestEntry)).scalars().first()
        ent.sha256_hash = "f" * 64
        db.commit()
    ver = client.post("/api/v1/integrity/baseline/verify").json()
    assert ver["valid"] is False and ver["status"] == "TAMPERED"

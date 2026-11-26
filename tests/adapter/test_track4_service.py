"""Independent process-level tests for track4_service.py (Stage 1)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest
from pqcrypto.kem import ml_kem_768 as ml_kem

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_PATH = REPO_ROOT / "track4_service.py"


def run_adapter(
    payload: dict[str, Any] | str,
    state_dir: Path | None = None,
    unset_state_dir: bool = False,
) -> tuple[dict[str, Any], subprocess.CompletedProcess[str]]:
    """Invoke track4_service.py as a fresh OS process and parse its single JSON stdout."""
    env = os.environ.copy()
    if unset_state_dir:
        env.pop("TRACK4_STATE_DIR", None)
    elif state_dir is not None:
        env["TRACK4_STATE_DIR"] = str(state_dir)

    stdin_text = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        [sys.executable, str(ADAPTER_PATH)],
        input=stdin_text,
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=False,
    )
    assert proc.returncode == 0, f"Unexpected exit code {proc.returncode}: {proc.stderr}"
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, f"Expected exactly 1 JSON line on stdout, got {len(lines)}: {proc.stdout!r}"
    parsed = json.loads(lines[0])
    assert isinstance(parsed, dict)
    return parsed, proc


@pytest.fixture()
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "track4_state"


def _setup_default(state_dir: Path) -> None:
    resp, _ = run_adapter(
        {
            "op": "setup",
            "owners": {
                "asset-alice": "alice",
                "asset-bob": "bob",
            },
            "contents": {
                "asset-alice": "TOP_SECRET_ALICE_BODY_123",
                "asset-bob": "TOP_SECRET_BOB_BODY_456",
            },
            "disabled": ["disabled-eve"],
            "key_material": {"synthetic_marker": "DO_NOT_LEAK_KEY_MARKER_999"},
        },
        state_dir=state_dir,
    )
    assert resp == {"ready": True}


def test_setup_and_reset_persists_across_processes(state_dir: Path) -> None:
    _setup_default(state_dir)
    read1, _ = run_adapter(
        {"op": "read", "actor": "alice", "asset": "asset-alice", "request_id": "req-1"},
        state_dir=state_dir,
    )
    assert read1["decision"] == "allow"
    assert read1["body"] == "TOP_SECRET_ALICE_BODY_123"

    # Reset via setup clears previous state and replaces contents
    resp, _ = run_adapter(
        {
            "op": "setup",
            "owners": {"asset-new": "carol"},
            "contents": {"asset-new": "NEW_CAROL_BODY"},
            "disabled_actors": [],
        },
        state_dir=state_dir,
    )
    assert resp == {"ready": True}

    old_read, _ = run_adapter(
        {"op": "read", "actor": "alice", "asset": "asset-alice", "request_id": "req-2"},
        state_dir=state_dir,
    )
    assert old_read == {"decision": "deny"}

    new_read, _ = run_adapter(
        {"op": "read", "actor": "carol", "asset": "asset-new", "request_id": "req-3"},
        state_dir=state_dir,
    )
    assert new_read["decision"] == "allow"
    assert new_read["body"] == "NEW_CAROL_BODY"


def test_owner_and_peer_isolation_and_wrong_owner_deny(state_dir: Path) -> None:
    _setup_default(state_dir)

    alice_resp, _ = run_adapter(
        {"op": "read", "actor": "alice", "asset": "asset-alice", "request_id": "r-a"},
        state_dir=state_dir,
    )
    assert alice_resp["decision"] == "allow"
    assert alice_resp["body"] == "TOP_SECRET_ALICE_BODY_123"

    bob_resp, _ = run_adapter(
        {"op": "read", "actor": "bob", "asset": "asset-bob", "request_id": "r-b"},
        state_dir=state_dir,
    )
    assert bob_resp["decision"] == "allow"
    assert bob_resp["body"] == "TOP_SECRET_BOB_BODY_456"

    wrong_resp, proc = run_adapter(
        {"op": "read", "actor": "bob", "asset": "asset-alice", "request_id": "r-wrong"},
        state_dir=state_dir,
    )
    assert wrong_resp == {"decision": "deny"}
    assert "TOP_SECRET_ALICE_BODY_123" not in proc.stdout
    assert "TOP_SECRET_ALICE_BODY_123" not in proc.stderr
    assert "DO_NOT_LEAK_KEY_MARKER_999" not in proc.stdout
    assert "DO_NOT_LEAK_KEY_MARKER_999" not in proc.stderr


def test_disabled_actor_denied(state_dir: Path) -> None:
    _setup_default(state_dir)
    resp, _ = run_adapter(
        {"op": "read", "actor": "disabled-eve", "asset": "asset-alice", "request_id": "r-eve"},
        state_dir=state_dir,
    )
    assert resp == {"decision": "deny"}


def test_revoke_persists_across_processes_and_preserves_peer(state_dir: Path) -> None:
    _setup_default(state_dir)

    rev_resp, _ = run_adapter(
        {"op": "revoke", "actor": "alice", "request_id": "req-rev-1"},
        state_dir=state_dir,
    )
    assert rev_resp == {"status": "revoked", "actor": "alice", "revoked": True}

    alice_after, proc = run_adapter(
        {"op": "read", "actor": "alice", "asset": "asset-alice", "request_id": "req-after"},
        state_dir=state_dir,
    )
    assert alice_after == {"decision": "deny"}
    assert "TOP_SECRET_ALICE_BODY_123" not in proc.stdout

    # Unaffected peer remains allowed
    bob_after, _ = run_adapter(
        {"op": "read", "actor": "bob", "asset": "asset-bob", "request_id": "req-bob-ok"},
        state_dir=state_dir,
    )
    assert bob_after["decision"] == "allow"
    assert bob_after["body"] == "TOP_SECRET_BOB_BODY_456"


def test_audit_correlation_and_boundary_sanitization(state_dir: Path) -> None:
    _setup_default(state_dir)

    run_adapter(
        {"op": "read", "actor": "alice", "asset": "asset-alice", "request_id": "req-audit-1"},
        state_dir=state_dir,
    )
    run_adapter(
        {
            "op": "read",
            "actor": "mallory\n{\"actor\":\"admin\",\"decision\":\"allow\"}",
            "asset": "asset-alice",
            "request_id": "req-audit-2",
        },
        state_dir=state_dir,
    )

    a1, _ = run_adapter({"op": "audit", "request_id": "req-audit-1"}, state_dir=state_dir)
    assert a1["found"] is True
    assert a1["request_id"] == "req-audit-1"
    assert a1["decision"] == "allow"

    a2, _ = run_adapter({"op": "audit", "request_id": "req-audit-2"}, state_dir=state_dir)
    assert a2["found"] is True
    assert a2["request_id"] == "req-audit-2"
    assert a2["decision"] == "deny"
    assert "\n" not in a2["actor"]

    missing, _ = run_adapter({"op": "audit", "request_id": "req-unknown"}, state_dir=state_dir)
    assert missing == {"found": False, "request_id": "req-unknown", "decision": "unknown"}


def test_protected_read_ml_kem_768_interop_and_deny(state_dir: Path) -> None:
    _setup_default(state_dir)
    pk, sk = ml_kem.generate_keypair()
    pk_b64 = base64.b64encode(pk).decode("ascii")
    challenge = "chal-2026-xyz"

    resp, proc = run_adapter(
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "asset-alice",
            "challenge": challenge,
            "public_key": pk_b64,
            "request_id": "req-pr-1",
        },
        state_dir=state_dir,
    )
    assert resp["decision"] == "allow"
    assert "ciphertext" in resp and "proof" in resp
    assert "TOP_SECRET_ALICE_BODY_123" not in proc.stdout
    assert "DO_NOT_LEAK_KEY_MARKER_999" not in proc.stdout
    assert "DO_NOT_LEAK_KEY_MARKER_999" not in proc.stderr

    ct_bytes = base64.b64decode(resp["ciphertext"].encode("ascii"), validate=True)
    assert len(ct_bytes) == ml_kem.CIPHERTEXT_SIZE
    shared_secret = ml_kem.decrypt(sk, ct_bytes)
    expected_mac = hmac.new(
        shared_secret,
        (challenge + "TOP_SECRET_ALICE_BODY_123").encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert resp["proof"] == expected_mac

    # Unauthorized actor denied without ciphertext or hmac
    denied, _ = run_adapter(
        {
            "op": "protected_read",
            "actor": "bob",
            "asset": "asset-alice",
            "challenge": challenge,
            "public_key": pk_b64,
            "request_id": "req-pr-deny",
        },
        state_dir=state_dir,
    )
    assert denied == {"decision": "deny"}


def test_protected_read_rejects_malformed_key_safely(state_dir: Path) -> None:
    _setup_default(state_dir)

    bad_b64, proc1 = run_adapter(
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "asset-alice",
            "challenge": "c1",
            "public_key": "not!valid!base64!",
        },
        state_dir=state_dir,
    )
    assert bad_b64["error"] == "invalid_public_key"
    assert "TOP_SECRET_ALICE_BODY_123" not in proc1.stdout
    assert "TOP_SECRET_ALICE_BODY_123" not in proc1.stderr
    assert "[track4_service]" in proc1.stderr

    wrong_len, proc2 = run_adapter(
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "asset-alice",
            "challenge": "c1",
            "public_key": base64.b64encode(b"short-key").decode("ascii"),
        },
        state_dir=state_dir,
    )
    assert wrong_len["error"] == "invalid_public_key"
    assert "[track4_service]" in proc2.stderr


def test_invalid_json_unknown_op_and_missing_fields(state_dir: Path) -> None:
    bad_json, proc = run_adapter("{not valid json", state_dir=state_dir)
    assert bad_json["error"] == "invalid_json"
    assert "[track4_service]" in proc.stderr

    non_obj, _ = run_adapter("[1, 2, 3]", state_dir=state_dir)
    assert non_obj["error"] == "invalid_json"

    unknown_op, _ = run_adapter({"op": "nonexistent_op"}, state_dir=state_dir)
    assert unknown_op["error"] == "unknown_operation"

    missing_field, _ = run_adapter({"op": "read", "actor": "alice"}, state_dir=state_dir)
    assert missing_field["error"] == "missing_field"


def test_default_os_temp_state_dir_fallback() -> None:
    default_state_file = Path(tempfile.gettempdir()) / "qshield_track4_state" / "adapter_state.json"
    if default_state_file.exists():
        default_state_file.unlink()
    try:
        resp, _ = run_adapter(
            {
                "op": "setup",
                "owners": {"tmp-asset": "tmp-owner"},
                "contents": {"tmp-asset": "TMP_BODY"},
            },
            unset_state_dir=True,
        )
        assert resp == {"ready": True}
        assert default_state_file.exists()

        read_resp, _ = run_adapter(
            {"op": "read", "actor": "tmp-owner", "asset": "tmp-asset", "request_id": "tmp-1"},
            unset_state_dir=True,
        )
        assert read_resp["decision"] == "allow"
        assert read_resp["body"] == "TMP_BODY"
    finally:
        if default_state_file.exists():
            default_state_file.unlink()

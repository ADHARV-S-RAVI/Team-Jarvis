#!/usr/bin/env python3
"""
Q-SHIELD Stage 11 Reproducible Benchmark Suite.

Uses time.perf_counter_ns(), warmups, repeated samples, and fixed seed=42.
Outputs:
- reports/benchmarks/latest.json
- reports/benchmarks/raw_samples.csv
- reports/benchmarks/summary.md
"""

from __future__ import annotations

import base64
import csv
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Callable

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
import psutil
from sqlalchemy.orm import sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.audit.service import append_audit_event, verify_db_audit_chain
from backend.app.backups.service import create_backup_manifest, verify_backup_manifest
from backend.app.crypto.provider import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_sha256,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_generate_keypair,
    random_bytes,
)
from backend.app.db.session import create_db_engine, get_db
from backend.app.detector.service import generate_synthetic_events, ingest_detector_events, run_deterministic_detection
from backend.app.keys.service import rotate_active_key
from backend.app.main import create_app
from backend.app.messaging.service import deliver_secure_message, send_secure_message
from backend.app.nodes.service import configure_simulated_nodes, propagate_revocation_to_nodes
from backend.app.policy.authz import AuthzRequest, evaluate_authorization
from backend.app.recovery.service import SimulatedCrashError, recover_rotation_journal, run_journaled_rotation
from backend.app.datalab.algorithms import streaming_sha256
from backend.app.identity_assurance.service import generate_register_options, has_fresh_assurance
from backend.app.integrity.service import initialize_baseline, run_application_scan, verify_manifest_integrity
from backend.app.services.foundation_service import (
    create_device,
    create_identity,
    create_resource,
    create_session,
    ensure_foundation_defaults,
)

SEED = 42
REPORTS_DIR = REPO_ROOT / "reports" / "benchmarks"


def _percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, math.ceil(p * len(sorted_vals)) - 1))
    return sorted_vals[idx]


def measure_op(
    name: str,
    fn: Callable[[], None],
    *,
    samples: int = 100,
    warmups: int = 5,
    raw_rows: list[dict[str, object]],
) -> dict[str, object]:
    errors = 0
    for _ in range(warmups):
        try:
            fn()
        except Exception:
            pass

    durations_ms: list[float] = []
    for i in range(samples):
        t0 = time.perf_counter_ns()
        try:
            fn()
            dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            durations_ms.append(dt_ms)
            raw_rows.append({"operation": name, "sample_idx": i, "duration_ms": round(dt_ms, 6), "status": "ok"})
        except Exception as exc:
            dt_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
            errors += 1
            raw_rows.append({"operation": name, "sample_idx": i, "duration_ms": round(dt_ms, 6), "status": f"err:{type(exc).__name__}"})

    s = sorted(durations_ms)
    mean_v = statistics.mean(s) if s else 0.0
    std_v = statistics.stdev(s) if len(s) > 1 else 0.0
    total_sec = sum(s) / 1000.0
    throughput = (len(s) / total_sec) if total_sec > 0 else 0.0

    return {
        "operation": name,
        "samples": samples,
        "warmups": warmups,
        "success": len(s),
        "errors": errors,
        "mean_ms": round(mean_v, 4),
        "p50_ms": round(_percentile(s, 0.50), 4),
        "p95_ms": round(_percentile(s, 0.95), 4),
        "p99_ms": round(_percentile(s, 0.99), 4),
        "min_ms": round(s[0], 4) if s else 0.0,
        "max_ms": round(s[-1], 4) if s else 0.0,
        "stddev_ms": round(std_v, 4),
        "throughput_ops_sec": round(throughput, 2),
    }


def _run_adapter(payload: dict[str, object], state_dir: Path) -> None:
    env = os.environ.copy()
    env["TRACK4_STATE_DIR"] = str(state_dir)
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "track4_service.py")],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        timeout=15,
        check=True,
    )
    json.loads(proc.stdout.strip())


def main() -> int:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    raw_rows: list[dict[str, object]] = []
    results: list[dict[str, object]] = []
    suite_start = time.perf_counter_ns()

    with tempfile.TemporaryDirectory(prefix="qshield-bench-") as tmp_str:
        tmp_dir = Path(tmp_str)
        os.environ["QSHIELD_KEY_STORE_DIR"] = str(tmp_dir / "keys")

        # 1. Adapter operations (cold-start process-per-request)
        adapter_dir = tmp_dir / "adapter_state"
        pk_kem, _ = ml_kem_generate_keypair()
        pk_b64 = base64.b64encode(pk_kem).decode("ascii")
        setup_payload = {"op": "setup", "owners": {"a1": "alice", "a2": "bob"}, "contents": {"a1": "BODY_1", "a2": "BODY_2"}, "disabled": []}
        _run_adapter(setup_payload, adapter_dir)

        results.append(measure_op("adapter_setup", lambda: _run_adapter(setup_payload, adapter_dir), samples=10, warmups=1, raw_rows=raw_rows))
        results.append(measure_op("adapter_read", lambda: _run_adapter({"op": "read", "actor": "alice", "asset": "a1", "request_id": "r1"}, adapter_dir), samples=10, warmups=1, raw_rows=raw_rows))
        results.append(measure_op("adapter_protected_read", lambda: _run_adapter({"op": "protected_read", "actor": "alice", "asset": "a1", "challenge": "c1", "public_key": pk_b64}, adapter_dir), samples=10, warmups=1, raw_rows=raw_rows))
        results.append(measure_op("adapter_audit", lambda: _run_adapter({"op": "audit", "request_id": "r1"}, adapter_dir), samples=10, warmups=1, raw_rows=raw_rows))
        results.append(measure_op("adapter_revoke", lambda: _run_adapter({"op": "revoke", "actor": "bob"}, adapter_dir), samples=10, warmups=1, raw_rows=raw_rows))

        # 2. Crypto microbenchmarks
        results.append(measure_op("ml_kem_768_keygen", lambda: ml_kem_generate_keypair(), samples=100, warmups=5, raw_rows=raw_rows))
        pk, sk = ml_kem_generate_keypair()
        ct, _ = ml_kem_encapsulate(pk)
        results.append(measure_op("ml_kem_768_encapsulate", lambda: ml_kem_encapsulate(pk), samples=100, warmups=5, raw_rows=raw_rows))
        results.append(measure_op("ml_kem_768_decapsulate", lambda: ml_kem_decapsulate(sk, ct), samples=100, warmups=5, raw_rows=raw_rows))

        ikm = random_bytes(32)
        results.append(measure_op("hkdf_sha256", lambda: hkdf_sha256(ikm, 32, info=b"bench"), samples=100, warmups=5, raw_rows=raw_rows))

        aes_key = random_bytes(32)
        for label, size_bytes, cnt in [("1KB", 1024, 100), ("100KB", 102400, 50), ("1MB", 1048576, 20), ("10MB", 10485760, 5)]:
            data = random_bytes(size_bytes)
            sealed = aes_gcm_encrypt(aes_key, data, aad=b"bench")
            results.append(measure_op(f"aes_256_gcm_encrypt_{label}", lambda d=data: aes_gcm_encrypt(aes_key, d, aad=b"bench"), samples=cnt, warmups=2, raw_rows=raw_rows))
            results.append(measure_op(f"aes_256_gcm_decrypt_{label}", lambda s=sealed: aes_gcm_decrypt(aes_key, nonce=s.nonce, ciphertext=s.ciphertext, tag=s.tag, aad=b"bench"), samples=cnt, warmups=2, raw_rows=raw_rows))

        # 3. Backend DB setup
        db_file = tmp_dir / "bench.db"
        db_url = f"sqlite:///{db_file}"
        cfg = Config(str(REPO_ROOT / "backend" / "alembic.ini"))
        cfg.set_main_option("sqlalchemy.url", db_url)
        command.upgrade(cfg, "head")
        engine = create_db_engine(db_url)
        TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

        with TestingSession() as db:
            ensure_foundation_defaults(db)
            create_identity(db, actor_id="alice", display_label="Alice", role="Owner/User", enabled=True, correlation_id="b0")
            create_identity(db, actor_id="bob", display_label="Bob", role="Owner/User", enabled=True, correlation_id="b0")
            create_identity(db, actor_id="secop", display_label="SecOp", role="Security Operator", enabled=True, correlation_id="b0")
            create_device(db, device_id="dev-a", owner_actor_id="alice", credential_fingerprint="fp-a-b", state="TRUSTED", correlation_id="b0")
            sess, tok = create_session(db, actor_id="alice", device_id="dev-a", peer_id="bob", ttl_seconds=3600, correlation_id="b0")
            create_resource(db, resource_id="res-b", owner_actor_id="alice", content_ref="vault://res-b", key_version=1, state="ACTIVE", correlation_id="b0")

            authz_req = AuthzRequest(actor_id="alice", session_id=sess.id, session_token=tok, device_id="dev-a", resource_id="res-b", action="resource:read", peer_id="bob")
            results.append(measure_op("policy_9step_evaluate", lambda: evaluate_authorization(db, authz_req), samples=100, warmups=5, raw_rows=raw_rows))

            # Audit append & verify
            results.append(measure_op("audit_append", lambda: append_audit_event(db, actor_id="alice", action="bench:op", target="res-b", decision="ALLOW", reason="BENCH", correlation_id="b1"), samples=100, warmups=5, raw_rows=raw_rows))
            results.append(measure_op("audit_verify_chain", lambda: verify_db_audit_chain(db), samples=20, warmups=2, raw_rows=raw_rows))

            # Backup create & verify
            manifest = create_backup_manifest(db, operator_actor_id="secop", correlation_id="b2")
            results.append(measure_op("backup_create", lambda: create_backup_manifest(db, operator_actor_id="secop", correlation_id="b2"), samples=20, warmups=2, raw_rows=raw_rows))
            results.append(measure_op("backup_verify", lambda: verify_backup_manifest(db, manifest=manifest), samples=50, warmups=3, raw_rows=raw_rows))

            # Node convergence 3, 5, 7 nodes
            for n_count in (3, 5, 7):
                configure_simulated_nodes(db, count=n_count)
                epoch_counter = [100]
                def _prop():
                    epoch_counter[0] += 1
                    propagate_revocation_to_nodes(db, subject_type="device", subject_id="dev-bench", epoch=epoch_counter[0])
                results.append(measure_op(f"node_revocation_convergence_{n_count}nodes", _prop, samples=20, warmups=2, raw_rows=raw_rows))

            # Key rotation & crash recovery
            results.append(measure_op("key_rotation_4phase", lambda: rotate_active_key(db, operator_actor_id="secop", reason="bench", retire_policy="RETIRED"), samples=10, warmups=1, raw_rows=raw_rows))
            def _crash_rec():
                try:
                    run_journaled_rotation(db, operator_actor_id="secop", reason="bench-crash", crash_at="before_commit")
                except SimulatedCrashError as exc:
                    recover_rotation_journal(db, operation_id=exc.operation_id, operator_actor_id="secop")
            results.append(measure_op("crash_recovery_pre_commit", _crash_rec, samples=10, warmups=1, raw_rows=raw_rows))

            # Detector ingest & run (100 events)
            syn_ev, _ = generate_synthetic_events(seed=SEED, count=100)
            results.append(measure_op("detector_ingest_100", lambda: ingest_detector_events(db, events=syn_ev), samples=10, warmups=1, raw_rows=raw_rows))
            results.append(measure_op("detector_run_100", lambda: run_deterministic_detection(db, approvals=[]), samples=10, warmups=1, raw_rows=raw_rows))

            # Messaging send & deliver + replay rejection
            def _msg_roundtrip():
                m = send_secure_message(db, sender_id="alice", recipient_id="bob", session_id=sess.id, plaintext="BENCH_MSG")
                deliver_secure_message(db, message_id=m.id, recipient_id="bob")
            results.append(measure_op("messaging_send_deliver", _msg_roundtrip, samples=25, warmups=2, raw_rows=raw_rows))

            replay_msg = send_secure_message(db, sender_id="alice", recipient_id="bob", session_id=sess.id, plaintext="REPLAY_BENCH")
            deliver_secure_message(db, message_id=replay_msg.id, recipient_id="bob")
            def _msg_replay_reject():
                try:
                    deliver_secure_message(db, message_id=replay_msg.id, recipient_id="bob")
                except Exception:
                    pass
            results.append(measure_op("messaging_replay_reject", _msg_replay_reject, samples=25, warmups=2, raw_rows=raw_rows))

            # Stage 13 Identity & Integrity benchmarks
            results.append(measure_op("webauthn_challenge_gen", lambda: generate_register_options(db, actor_id="alice"), samples=50, warmups=3, raw_rows=raw_rows))
            results.append(measure_op("identity_freshness_check", lambda: has_fresh_assurance(db, "alice"), samples=50, warmups=3, raw_rows=raw_rows))

            bench_1mb = tmp_dir / "bench_1mb.bin"
            bench_1mb.write_bytes(os.urandom(1024 * 1024))
            bench_10mb = tmp_dir / "bench_10mb.bin"
            bench_10mb.write_bytes(os.urandom(10 * 1024 * 1024))
            results.append(measure_op("integrity_sha256_1MB", lambda: streaming_sha256(bench_1mb), samples=25, warmups=2, raw_rows=raw_rows))
            results.append(measure_op("integrity_sha256_10MB", lambda: streaming_sha256(bench_10mb), samples=10, warmups=1, raw_rows=raw_rows))

            scan_dir = tmp_dir / "scan_100"
            scan_dir.mkdir(exist_ok=True)
            for idx in range(100):
                (scan_dir / f"f_{idx:03d}.py").write_text(f"# deterministic file {idx}\nval = {idx}\n", encoding="utf-8")
            initialize_baseline(db, operator_actor_id="secop", app_root=scan_dir)
            results.append(measure_op("integrity_manifest_verify", lambda: verify_manifest_integrity(db), samples=25, warmups=2, raw_rows=raw_rows))
            results.append(measure_op("integrity_scan_100_files", lambda: run_application_scan(db, actor_id="secop", app_root=scan_dir), samples=5, warmups=1, raw_rows=raw_rows))

        # 4. App startup & API latency (sequential + controlled concurrency)
        results.append(measure_op("app_startup_create_app", lambda: create_app(), samples=10, warmups=1, raw_rows=raw_rows))
        app = create_app()
        def _override_db():
            d = TestingSession()
            try:
                yield d
            finally:
                d.close()
        app.dependency_overrides[get_db] = _override_db
        client = TestClient(app)
        results.append(measure_op("api_get_health", lambda: client.get("/api/v1/health"), samples=100, warmups=5, raw_rows=raw_rows))
        results.append(measure_op("api_post_policy_evaluate", lambda: client.post("/api/v1/policy/evaluate", json={"actor_id": "alice", "session_id": sess.id, "device_id": "dev-a", "resource_id": "res-b", "action": "resource:read", "peer_id": "bob", "session_token": tok}), samples=100, warmups=5, raw_rows=raw_rows))

        from concurrent.futures import ThreadPoolExecutor
        def _concurrent_health():
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: client.get("/api/v1/health"), range(4)))
        results.append(measure_op("api_concurrent_4w_health", _concurrent_health, samples=25, warmups=2, raw_rows=raw_rows))
        app.dependency_overrides.clear()
        engine.dispose()

    proc_info = psutil.Process()
    mem_rss_mb = round(proc_info.memory_info().rss / (1024 * 1024), 2)
    cpu_t = proc_info.cpu_times()
    cpu_user_s = round(cpu_t.user, 3)
    cpu_system_s = round(cpu_t.system, 3)
    total_duration_s = round((time.perf_counter_ns() - suite_start) / 1_000_000_000.0, 2)

    env_meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "seed": SEED,
        "peak_rss_mb": mem_rss_mb,
        "cpu_user_s": cpu_user_s,
        "cpu_system_s": cpu_system_s,
        "suite_duration_s": total_duration_s,
    }

    # Write JSON
    latest_json = {"environment": env_meta, "benchmarks": results}
    (REPORTS_DIR / "latest.json").write_text(json.dumps(latest_json, indent=2), encoding="utf-8")

    # Write CSV
    with (REPORTS_DIR / "raw_samples.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["operation", "sample_idx", "duration_ms", "status"])
        writer.writeheader()
        writer.writerows(raw_rows)

    # Write Markdown summary
    md_lines = [
        "# Q-SHIELD — Benchmark Summary (Stage 11)",
        "",
        f"- **Timestamp (UTC):** {env_meta['timestamp_utc']}",
        f"- **OS / Python:** {env_meta['os']} / Python {env_meta['python_version']}",
        f"- **CPU Cores:** {env_meta['cpu_count']} | **CPU Time (user/sys):** {cpu_user_s}s / {cpu_system_s}s | **Process RSS:** {mem_rss_mb} MB | **Total Duration:** {total_duration_s} s",
        f"- **Seed:** `{SEED}` | **Timer:** `time.perf_counter_ns` | **Memory/CPU Method:** `psutil.Process().memory_info().rss` & `cpu_times()`",
        "- **Notes:** `node_revocation_convergence_*` measures in-process **simulated** nodes (`3`, `5`, `7`). `ML-DSA` is **NOT IMPLEMENTED** (not used in Q-SHIELD).",
        "",
        "| Operation | Samples | Errors | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Max (ms) | StdDev (ms) | Throughput (ops/s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        md_lines.append(
            f"| `{r['operation']}` | {r['samples']} | {r['errors']} | {r['mean_ms']} | {r['p50_ms']} | {r['p95_ms']} | {r['p99_ms']} | {r['max_ms']} | {r['stddev_ms']} | {r['throughput_ops_sec']} |"
        )
    (REPORTS_DIR / "summary.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    print(f"Benchmarks complete: {len(results)} operations, {len(raw_rows)} raw samples, duration={total_duration_s}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Application File Integrity Monitoring, HMAC-protected Manifest, and Baseline Governance."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.audit.service import append_audit_event
from backend.app.crypto.provider import hkdf_sha256, hmac_sha256_hex
from backend.app.datalab.algorithms import streaming_sha256
from backend.app.db.models import (
    BaselineChangeRequest,
    Incident,
    IntegrityFinding,
    IntegrityManifest,
    IntegrityManifestEntry,
    IntegrityScan,
)
from backend.app.devices.service import DomainPermissionError, _require_operator
from backend.app.keys.service import KeyMaterialStore
from backend.app.services.foundation_service import DomainNotFoundError, DomainValidationError
from backend.app.telemetry.bus import telemetry_bus

SCANNER_VERSION = "1.0.0"
DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SCAN_SUBPATHS = ("backend/app", "track4_service.py", "frontend/src")
EXCLUDED_DIRS = {"__pycache__", "node_modules", ".git", ".qshield_keys", ".qshield_uploads", ".pytest_cache", "dist"}
EXCLUDED_EXTS = {".pyc", ".pyo", ".db", ".db-wal", ".db-shm", ".key"}
MAX_SCAN_FILE_BYTES = 100 * 1024 * 1024  # 100 MiB safety limit per file


def _derive_manifest_hmac_key(key_store: KeyMaterialStore | None = None) -> bytes:
    store = key_store or KeyMaterialStore()
    kek = store._get_or_init_master_key()
    try:
        return hkdf_sha256(kek, length=32, info=b"qshield:integrity-manifest-hmac:v1")
    finally:
        del kek


def _canonical_root_hash(entries: list[tuple[str, str, int]]) -> str:
    canonical = json.dumps(
        sorted([(p, h, s) for p, h, s in entries], key=lambda x: x[0]),
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sign_root_hash(root_hash: str, key_store: KeyMaterialStore | None = None) -> str:
    key = _derive_manifest_hmac_key(key_store)
    try:
        return hmac_sha256_hex(key, root_hash.encode("ascii"))
    finally:
        del key


def _is_excluded(rel_path: str, name: str) -> bool:
    parts = Path(rel_path).parts
    if any(part in EXCLUDED_DIRS for part in parts):
        return True
    if Path(name).suffix.lower() in EXCLUDED_EXTS:
        return True
    return False


def _collect_permitted_files(
    app_root: Path,
    *,
    max_file_bytes: int = MAX_SCAN_FILE_BYTES,
) -> tuple[list[dict[str, object]], int, int]:
    """Walk permitted Q-SHIELD app paths safely with symlink & traversal guards.

    Returns (eligible_records, excluded_count, unreadable_findings).
    """
    resolved_root = app_root.resolve()
    targets: list[Path] = []
    # Support custom app_root (e.g. test temp dir) or default Q-SHIELD repo subpaths
    default_exists = any((resolved_root / sub).exists() for sub in DEFAULT_SCAN_SUBPATHS)
    if resolved_root == DEFAULT_REPO_ROOT and default_exists:
        for sub in DEFAULT_SCAN_SUBPATHS:
            p = resolved_root / sub
            if p.exists():
                targets.append(p)
    else:
        targets.append(resolved_root)

    records: list[dict[str, object]] = []
    unreadable: list[dict[str, object]] = []
    excluded_count = 0
    seen_rel: set[str] = set()

    def _inspect_file(fp: Path) -> None:
        nonlocal excluded_count
        try:
            if fp.is_symlink():
                real_fp = fp.resolve()
                if not str(real_fp).startswith(str(resolved_root)):
                    excluded_count += 1
                    return
            rel = fp.relative_to(resolved_root).as_posix()
        except Exception:
            excluded_count += 1
            return

        if ".." in Path(rel).parts or rel in seen_rel:
            return
        seen_rel.add(rel)

        if _is_excluded(rel, fp.name):
            excluded_count += 1
            return

        try:
            st = fp.stat()
            if st.st_size > max_file_bytes:
                excluded_count += 1
                return
            sha = streaming_sha256(fp)
            records.append(
                {
                    "relative_path": rel,
                    "sha256_hash": sha,
                    "file_size": int(st.st_size),
                    "file_type": fp.suffix.lstrip(".").lower() or "file",
                }
            )
        except OSError:
            unreadable.append(
                {
                    "relative_path": rel,
                    "file_size": 0,
                    "file_type": fp.suffix.lstrip(".").lower() or "file",
                }
            )

    for target in targets:
        if target.is_file():
            _inspect_file(target)
        elif target.is_dir():
            for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
                dirnames[:] = sorted([d for d in dirnames if d not in EXCLUDED_DIRS])
                for fn in sorted(filenames):
                    _inspect_file(Path(dirpath) / fn)

    return records, excluded_count, len(unreadable)


def get_active_manifest(db: Session) -> IntegrityManifest | None:
    return db.execute(
        select(IntegrityManifest)
        .where(IntegrityManifest.status == "ACTIVE")
        .order_by(IntegrityManifest.manifest_version.desc())
        .limit(1)
    ).scalar_one_or_none()


def initialize_baseline(
    db: Session,
    *,
    operator_actor_id: str,
    app_root: Path | None = None,
    key_store: KeyMaterialStore | None = None,
    correlation_id: str = "integrity-init",
) -> IntegrityManifest:
    _require_operator(db, operator_actor_id)
    root = app_root or DEFAULT_REPO_ROOT
    records, _excluded, _unreadable = _collect_permitted_files(root)

    # Mark existing ACTIVE manifests SUPERSEDED
    prev = db.execute(select(IntegrityManifest).where(IntegrityManifest.status == "ACTIVE")).scalars().all()
    max_ver = 0
    for m in prev:
        m.status = "SUPERSEDED"
        max_ver = max(max_ver, m.manifest_version)

    entries_tuples = [(str(r["relative_path"]), str(r["sha256_hash"]), int(r["file_size"])) for r in records]
    root_hash = _canonical_root_hash(entries_tuples)
    sig = _sign_root_hash(root_hash, key_store)
    now = datetime.now(timezone.utc)

    manifest = IntegrityManifest(
        manifest_version=max_ver + 1,
        root_hash=root_hash,
        manifest_hmac=sig,
        scanner_version=SCANNER_VERSION,
        status="ACTIVE",
        created_by=operator_actor_id,
        approved_by=operator_actor_id,
        approved_at=now,
    )
    db.add(manifest)
    db.flush()

    for r in records:
        db.add(
            IntegrityManifestEntry(
                manifest_id=manifest.id,
                relative_path=str(r["relative_path"]),
                sha256_hash=str(r["sha256_hash"]),
                file_size=int(r["file_size"]),
                file_type=str(r["file_type"]),
                baseline_status="VERIFIED",
            )
        )

    db.commit()
    db.refresh(manifest)

    append_audit_event(
        db,
        actor_id=operator_actor_id,
        action="integrity:baseline:initialize",
        target=manifest.id,
        decision="ALLOW",
        reason=f"Baseline v{manifest.manifest_version} initialized ({len(records)} files, root={root_hash[:12]})",
        correlation_id=correlation_id,
    )
    telemetry_bus.publish("baseline_initialized", {"manifest_id": manifest.id, "version": manifest.manifest_version, "files": len(records)})
    return manifest


def verify_manifest_integrity(
    db: Session,
    *,
    manifest_id: str | None = None,
    key_store: KeyMaterialStore | None = None,
    correlation_id: str = "manifest-verify",
) -> dict[str, object]:
    manifest = db.get(IntegrityManifest, manifest_id) if manifest_id else get_active_manifest(db)
    if manifest is None:
        return {"valid": False, "status": "BASELINE_UNAVAILABLE", "reason": "No active baseline manifest exists"}

    entries = list(
        db.execute(select(IntegrityManifestEntry).where(IntegrityManifestEntry.manifest_id == manifest.id))
        .scalars()
        .all()
    )
    recomputed_root = _canonical_root_hash([(e.relative_path, e.sha256_hash, e.file_size) for e in entries])
    expected_hmac = _sign_root_hash(recomputed_root, key_store)

    if recomputed_root != manifest.root_hash or expected_hmac != manifest.manifest_hmac:
        manifest.status = "TAMPERED"
        db.add(
            Incident(
                incident_type="INTEGRITY_BASELINE_TAMPER",
                severity="CRITICAL",
                status="OPEN",
                initiator_actor_id="integrity-verifier",
                target_subject_type="manifest",
                target_subject_id=manifest.id,
                reason="Integrity manifest canonical hash or HMAC verification failed",
                confirmed=False,
            )
        )
        append_audit_event(
            db,
            actor_id="integrity-verifier",
            action="integrity:manifest:verify",
            target=manifest.id,
            decision="DENY",
            reason="MANIFEST_TAMPER_DETECTED",
            correlation_id=correlation_id,
        )
        db.commit()
        return {"valid": False, "status": "TAMPERED", "reason": "Manifest hash or HMAC mismatch", "manifest_id": manifest.id}

    append_audit_event(
        db,
        actor_id="integrity-verifier",
        action="integrity:manifest:verify",
        target=manifest.id,
        decision="ALLOW",
        reason=f"Manifest v{manifest.manifest_version} verified ({len(entries)} entries)",
        correlation_id=correlation_id,
    )
    return {
        "valid": True,
        "status": manifest.status,
        "manifest_id": manifest.id,
        "manifest_version": manifest.manifest_version,
        "entry_count": len(entries),
        "root_hash": manifest.root_hash,
    }


def run_application_scan(
    db: Session,
    *,
    actor_id: str = "secop",
    app_root: Path | None = None,
    key_store: KeyMaterialStore | None = None,
    max_duration_seconds: float = 30.0,
    correlation_id: str = "integrity-scan",
) -> IntegrityScan:
    t0 = time.perf_counter_ns()
    root = app_root or DEFAULT_REPO_ROOT
    manifest = get_active_manifest(db)

    scan = IntegrityScan(
        manifest_id=manifest.id if manifest else None,
        scan_scope="APPLICATION_FILES",
        scan_status="RUNNING",
        correlation_id=correlation_id,
    )
    db.add(scan)
    db.flush()

    if manifest is not None:
        ver = verify_manifest_integrity(db, manifest_id=manifest.id, key_store=key_store, correlation_id=correlation_id)
        if not ver["valid"]:
            scan.scan_status = "FAILED"
            scan.duration_ms = int((time.perf_counter_ns() - t0) / 1_000_000)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(scan)
            return scan

    records, excluded_count, unreadable_count = _collect_permitted_files(root)
    actual_map = {str(r["relative_path"]): r for r in records}

    baseline_entries = (
        list(
            db.execute(select(IntegrityManifestEntry).where(IntegrityManifestEntry.manifest_id == manifest.id))
            .scalars()
            .all()
        )
        if manifest
        else []
    )
    expected_map = {e.relative_path: e for e in baseline_entries}

    verified = 0
    modified = 0
    missing = 0
    unexpected = 0

    for rel, rec in actual_map.items():
        if (time.perf_counter_ns() - t0) / 1e9 > max_duration_seconds:
            scan.scan_status = "PARTIAL"
            break

        exp = expected_map.get(rel)
        if manifest is None:
            ftype = "BASELINE_UNAVAILABLE"
            sev = "MEDIUM"
            exp_hash = None
        elif exp is None:
            ftype = "UNEXPECTED"
            sev = "HIGH"
            exp_hash = None
            unexpected += 1
        elif exp.sha256_hash != rec["sha256_hash"]:
            ftype = "MODIFIED"
            sev = "CRITICAL"
            exp_hash = exp.sha256_hash
            modified += 1
        else:
            ftype = "VERIFIED"
            sev = "INFO"
            exp_hash = exp.sha256_hash
            verified += 1

        db.add(
            IntegrityFinding(
                scan_id=scan.id,
                relative_path=rel,
                file_type=str(rec["file_type"]),
                file_size=int(rec["file_size"]),
                expected_hash=exp_hash,
                actual_hash=str(rec["sha256_hash"]),
                finding_type=ftype,
                severity=sev,
            )
        )

    for rel, exp in expected_map.items():
        if rel not in actual_map:
            missing += 1
            db.add(
                IntegrityFinding(
                    scan_id=scan.id,
                    relative_path=rel,
                    file_type=exp.file_type,
                    file_size=exp.file_size,
                    expected_hash=exp.sha256_hash,
                    actual_hash=None,
                    finding_type="MISSING",
                    severity="CRITICAL",
                )
            )

    if scan.scan_status == "RUNNING":
        scan.scan_status = "COMPLETED"
    scan.files_scanned = len(actual_map) + unreadable_count
    scan.files_verified = verified
    scan.files_modified = modified
    scan.files_missing = missing
    scan.files_unexpected = unexpected
    scan.files_unreadable = unreadable_count
    scan.files_excluded = excluded_count
    scan.duration_ms = int((time.perf_counter_ns() - t0) / 1_000_000)
    scan.completed_at = datetime.now(timezone.utc)

    # Raise security incidents automatically if tampering or missing files detected
    if modified > 0 or missing > 0:
        db.add(
            Incident(
                incident_type="INTEGRITY_APPLICATION_DRIFT",
                severity="CRITICAL",
                status="OPEN",
                initiator_actor_id="integrity-scanner",
                target_subject_type="scan",
                target_subject_id=scan.id,
                reason=f"Application integrity mismatch: {modified} modified, {missing} missing, {unexpected} unexpected",
                confirmed=False,
            )
        )

    append_audit_event(
        db,
        actor_id=actor_id,
        action="integrity:scan:application",
        target=scan.id,
        decision="DENY" if (modified > 0 or missing > 0) else "ALLOW",
        reason=f"scanned={scan.files_scanned} verified={verified} modified={modified} missing={missing} unexpected={unexpected}",
        correlation_id=correlation_id,
    )
    db.commit()
    db.refresh(scan)
    telemetry_bus.publish("integrity_scan_complete", {"scan_id": scan.id, "modified": modified, "missing": missing, "unexpected": unexpected})
    return scan


def record_user_selected_scan(
    db: Session,
    *,
    actor_id: str,
    entries: list[dict[str, object]],
    correlation_id: str = "user-scan",
) -> IntegrityScan:
    """Inspect user-selected file hashes computed client-side (no file contents uploaded)."""
    t0 = time.perf_counter_ns()
    scan = IntegrityScan(
        scan_scope="USER_SELECTED_METADATA",
        scan_status="COMPLETED",
        files_scanned=len(entries),
        files_verified=0,
        correlation_id=correlation_id,
        completed_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.flush()

    seen: dict[str, str] = {}
    for item in entries[:500]:
        rel = str(item.get("relative_path") or "selected_file")[:250]
        if ".." in Path(rel).parts:
            raise DomainValidationError("Path traversal rejected in user-selected scan")
        actual = str(item.get("sha256_hash") or "").strip().lower()
        expected = item.get("expected_hash")
        exp_clean = str(expected).strip().lower() if expected else None

        if exp_clean:
            ftype = "VERIFIED" if actual == exp_clean else "MODIFIED"
            sev = "INFO" if ftype == "VERIFIED" else "HIGH"
        else:
            ftype = "BASELINE_UNAVAILABLE"
            sev = "INFO"

        seen[rel] = actual
        if ftype == "VERIFIED":
            scan.files_verified += 1
        elif ftype == "MODIFIED":
            scan.files_modified += 1

        db.add(
            IntegrityFinding(
                scan_id=scan.id,
                relative_path=rel,
                file_type=str(item.get("file_type") or "user_selected"),
                file_size=int(item.get("file_size") or 0),
                expected_hash=exp_clean,
                actual_hash=actual,
                finding_type=ftype,
                severity=sev,
            )
        )

    scan.duration_ms = max(1, int((time.perf_counter_ns() - t0) / 1_000_000))
    append_audit_event(
        db,
        actor_id=actor_id,
        action="integrity:scan:user_selected",
        target=scan.id,
        decision="ALLOW",
        reason=f"User-selected metadata scan ({len(entries)} items hashed client-side)",
        correlation_id=correlation_id,
    )
    db.commit()
    db.refresh(scan)
    return scan


def request_baseline_update(
    db: Session,
    *,
    requested_by: str,
    reason: str,
    scan_id: str | None = None,
    correlation_id: str = "baseline-req",
) -> BaselineChangeRequest:
    if not reason.strip():
        raise DomainValidationError("Reason is required for baseline update request")
    manifest = get_active_manifest(db)
    if manifest is None:
        raise DomainNotFoundError("No active baseline manifest exists")

    findings = []
    if scan_id:
        rows = db.execute(
            select(IntegrityFinding).where(
                IntegrityFinding.scan_id == scan_id,
                IntegrityFinding.finding_type.in_(("MODIFIED", "MISSING", "UNEXPECTED")),
            )
        ).scalars().all()
        findings = [
            {"relative_path": f.relative_path, "finding_type": f.finding_type, "actual_hash": f.actual_hash, "file_size": f.file_size, "file_type": f.file_type}
            for f in rows
        ]

    # Compute proposed hash preview
    new_preview_hash = hashlib.sha256(
        (manifest.root_hash + json.dumps(findings, sort_keys=True)).encode("utf-8")
    ).hexdigest()

    req = BaselineChangeRequest(
        manifest_id=manifest.id,
        requested_by=requested_by,
        reason=reason.strip(),
        changes_json=json.dumps(findings),
        previous_manifest_hash=manifest.root_hash,
        new_manifest_hash=new_preview_hash,
        status="PENDING",
    )
    db.add(req)
    db.commit()
    db.refresh(req)

    append_audit_event(
        db,
        actor_id=requested_by,
        action="integrity:baseline:change_requested",
        target=req.id,
        decision="ALLOW",
        reason=reason.strip(),
        correlation_id=correlation_id,
    )
    return req


def approve_or_reject_baseline_change(
    db: Session,
    *,
    request_id: str,
    operator_actor_id: str,
    approve: bool,
    app_root: Path | None = None,
    key_store: KeyMaterialStore | None = None,
    correlation_id: str = "baseline-resolve",
) -> BaselineChangeRequest:
    _require_operator(db, operator_actor_id)
    req = db.get(BaselineChangeRequest, request_id)
    if req is None:
        raise DomainNotFoundError("Baseline change request not found")
    if req.status != "PENDING":
        raise DomainValidationError(f"Request already resolved ({req.status})")

    now = datetime.now(timezone.utc)
    if approve:
        new_manifest = initialize_baseline(
            db,
            operator_actor_id=operator_actor_id,
            app_root=app_root,
            key_store=key_store,
            correlation_id=correlation_id,
        )
        req.status = "APPROVED"
        req.new_manifest_hash = new_manifest.root_hash
    else:
        req.status = "REJECTED"

    req.approved_by = operator_actor_id
    req.resolved_at = now
    ev = append_audit_event(
        db,
        actor_id=operator_actor_id,
        action=f"integrity:baseline:{'approved' if approve else 'rejected'}",
        target=req.id,
        decision="ALLOW",
        reason=f"{req.status}: {req.reason}",
        correlation_id=correlation_id,
    )
    req.audit_ref = ev.event_id
    db.commit()
    db.refresh(req)
    return req

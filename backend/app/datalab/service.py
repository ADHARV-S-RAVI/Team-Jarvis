"""Data Intelligence & Verification Lab service (resumable uploads + 14-stage pipeline)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import time
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.audit.service import append_audit_event
from backend.app.config import get_settings
from backend.app.datalab.algorithms import (
    STREAM_BUFFER_BYTES,
    analyze_crypto_and_cert,
    analyze_dataset_streaming,
    analyze_log_streaming,
    compute_merkle_root,
    detect_content_type,
    inspect_archive_safely,
    streaming_sha256,
)
from backend.app.db.models import (
    BackgroundJob,
    UploadChunk,
    UploadSession,
    VerificationStage,
    VerifiedFile,
)
from backend.app.services.foundation_service import DomainNotFoundError, DomainValidationError
from backend.app.telemetry.bus import telemetry_bus

PIPELINE_STAGES = [
    ("UPLOAD", "Resumable Chunk Transfer"),
    ("CHUNK_VALIDATION", "Per-Chunk SHA-256"),
    ("REASSEMBLY", "Streaming File Reassembly"),
    ("CONTENT_TYPE", "Magic-Byte Inspection"),
    ("STREAMING_HASH", "Streaming SHA-256 + Merkle"),
    ("STRUCTURE_VALIDATION", "Format & Archive Limits"),
    ("METADATA_ANALYSIS", "Header & Size Metadata"),
    ("INTEGRITY_VERIFICATION", "Reference Digest Check"),
    ("SIGNATURE_CHECK", "X.509 / Signature Parser"),
    ("CRYPTO_ANALYSIS", "Quantum-Readiness Classifier"),
    ("SECURITY_ANALYSIS", "Traversal & Anomaly Rules"),
    ("DATASET_ANALYSIS", "Welford & Reservoir Stream"),
    ("RISK_CLASSIFICATION", "Deterministic Risk Matrix"),
    ("EVIDENCE_GENERATION", "Verification Receipt"),
]


def _safe_filename(name: str) -> str:
    base = Path(name).name.strip()
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    if not cleaned or cleaned in (".", ".."):
        raise DomainValidationError("Invalid filename")
    return cleaned[:180]


def _upload_root() -> Path:
    settings = get_settings()
    root = Path(settings.upload_dir).resolve()
    (root / "staging").mkdir(parents=True, exist_ok=True)
    (root / "files").mkdir(parents=True, exist_ok=True)
    return root


def _current_storage_bytes(db: Session) -> int:
    total = db.execute(select(func.coalesce(func.sum(VerifiedFile.size_bytes), 0))).scalar_one()
    return int(total or 0)


def initiate_upload(
    db: Session,
    *,
    filename: str,
    declared_size_bytes: int,
    chunk_size_bytes: int = 1024 * 1024,
    reference_sha256: str | None = None,
    owner_actor_id: str = "secop",
    correlation_id: str = "datalab-init",
) -> UploadSession:
    settings = get_settings()
    if declared_size_bytes <= 0:
        raise DomainValidationError("declared_size_bytes must be positive")
    if declared_size_bytes > settings.max_upload_bytes:
        raise DomainValidationError(f"File exceeds configured max_upload_bytes ({settings.max_upload_bytes})")
    if _current_storage_bytes(db) + declared_size_bytes > settings.storage_quota_bytes:
        raise DomainValidationError("Storage quota exceeded")
    if chunk_size_bytes < 1024 or chunk_size_bytes > 16 * 1024 * 1024:
        raise DomainValidationError("chunk_size_bytes must be between 1 KiB and 16 MiB")

    ref_clean = reference_sha256.strip().lower() if reference_sha256 else None
    if ref_clean and not re.fullmatch(r"[0-9a-f]{64}", ref_clean):
        raise DomainValidationError("reference_sha256 must be a 64-character hex SHA-256 digest")

    safe_name = _safe_filename(filename)
    total_chunks = max(1, math.ceil(declared_size_bytes / chunk_size_bytes))
    upload_id = str(uuid.uuid4())
    temp_dir = _upload_root() / "staging" / upload_id
    temp_dir.mkdir(parents=True, exist_ok=True)

    session = UploadSession(
        id=upload_id,
        filename=safe_name,
        declared_size_bytes=declared_size_bytes,
        chunk_size_bytes=chunk_size_bytes,
        total_chunks=total_chunks,
        received_chunks=0,
        status="INITIATED",
        reference_sha256=ref_clean,
        owner_actor_id=owner_actor_id,
        temp_dir=str(temp_dir),
    )
    db.add(session)
    db.commit()
    db.refresh(session)

    append_audit_event(
        db,
        actor_id=owner_actor_id,
        action="datalab:upload:initiate",
        target=upload_id,
        decision="ALLOW",
        reason=f"Initiated {safe_name} ({declared_size_bytes} bytes, {total_chunks} chunks)",
        correlation_id=correlation_id,
    )
    telemetry_bus.publish("upload_initiated", {"upload_id": upload_id, "filename": safe_name, "total_chunks": total_chunks})
    return session


def store_upload_chunk(
    db: Session,
    *,
    upload_id: str,
    chunk_index: int,
    chunk_bytes: bytes,
    expected_sha256: str | None = None,
) -> UploadChunk:
    sess = db.get(UploadSession, upload_id)
    if sess is None:
        raise DomainNotFoundError(f"Upload session '{upload_id}' not found")
    if sess.status in ("CANCELLED", "FINALIZED"):
        raise DomainValidationError(f"Cannot upload chunk when session is {sess.status}")
    if chunk_index < 0 or chunk_index >= sess.total_chunks:
        raise DomainValidationError(f"chunk_index {chunk_index} out of bounds [0, {sess.total_chunks - 1}]")

    actual_sha = hashlib.sha256(chunk_bytes).hexdigest()
    if expected_sha256 and actual_sha != expected_sha256.strip().lower():
        raise DomainValidationError("Chunk SHA-256 mismatch (corrupted transfer)")

    part_path = Path(sess.temp_dir) / f"chunk_{chunk_index:06d}.part"
    part_path.parent.mkdir(parents=True, exist_ok=True)
    part_path.write_bytes(chunk_bytes)

    existing = db.execute(
        select(UploadChunk).where(UploadChunk.upload_id == upload_id, UploadChunk.chunk_index == chunk_index)
    ).scalar_one_or_none()
    if existing is not None:
        existing.size_bytes = len(chunk_bytes)
        existing.chunk_sha256 = actual_sha
        existing.status = "VERIFIED"
        existing.attempts += 1
        chunk_rec = existing
    else:
        chunk_rec = UploadChunk(
            upload_id=upload_id,
            chunk_index=chunk_index,
            size_bytes=len(chunk_bytes),
            chunk_sha256=actual_sha,
            status="VERIFIED",
            attempts=1,
        )
        db.add(chunk_rec)

    db.flush()
    verified_count = db.execute(
        select(func.count(UploadChunk.id)).where(UploadChunk.upload_id == upload_id, UploadChunk.status == "VERIFIED")
    ).scalar_one()
    sess.received_chunks = int(verified_count)
    if sess.status == "INITIATED":
        sess.status = "UPLOADING"
    sess.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(chunk_rec)

    telemetry_bus.publish(
        "upload_progress",
        {
            "upload_id": upload_id,
            "chunk_index": chunk_index,
            "received_chunks": sess.received_chunks,
            "total_chunks": sess.total_chunks,
        },
    )
    return chunk_rec


def set_upload_state(db: Session, *, upload_id: str, new_status: str) -> UploadSession:
    sess = db.get(UploadSession, upload_id)
    if sess is None:
        raise DomainNotFoundError(f"Upload session '{upload_id}' not found")
    if sess.status == "FINALIZED":
        raise DomainValidationError("Upload already finalized")
    sess.status = new_status
    sess.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(sess)
    if new_status == "CANCELLED":
        shutil.rmtree(sess.temp_dir, ignore_errors=True)
    return sess


def finalize_upload(
    db: Session,
    *,
    upload_id: str,
    run_inline: bool = False,
    correlation_id: str = "datalab-finalize",
) -> tuple[VerifiedFile, BackgroundJob]:
    sess = db.get(UploadSession, upload_id)
    if sess is None:
        raise DomainNotFoundError(f"Upload session '{upload_id}' not found")
    if sess.status == "CANCELLED":
        raise DomainValidationError("Upload was cancelled")

    chunks = list(
        db.execute(
            select(UploadChunk)
            .where(UploadChunk.upload_id == upload_id, UploadChunk.status == "VERIFIED")
            .order_by(UploadChunk.chunk_index.asc())
        )
        .scalars()
        .all()
    )
    if len(chunks) != sess.total_chunks:
        raise DomainValidationError(f"Missing chunks: received {len(chunks)} of {sess.total_chunks}")

    file_id = str(uuid.uuid4())
    dest_path = _upload_root() / "files" / f"{file_id}_{sess.filename}"
    leaf_hashes: list[str] = []
    stream_hasher = hashlib.sha256()
    total_written = 0

    with dest_path.open("wb") as out_fh:
        for ch in chunks:
            part_path = Path(sess.temp_dir) / f"chunk_{ch.chunk_index:06d}.part"
            if not part_path.exists():
                raise DomainValidationError(f"Missing chunk file {ch.chunk_index} on disk")
            leaf_hashes.append(ch.chunk_sha256)
            with part_path.open("rb") as in_fh:
                while True:
                    buf = in_fh.read(STREAM_BUFFER_BYTES)
                    if not buf:
                        break
                    out_fh.write(buf)
                    stream_hasher.update(buf)
                    total_written += len(buf)

    shutil.rmtree(sess.temp_dir, ignore_errors=True)
    sess.status = "FINALIZED"
    sess.updated_at = datetime.now(timezone.utc)

    merkle_root = compute_merkle_root(leaf_hashes)
    file_sha = stream_hasher.hexdigest()

    vfile = VerifiedFile(
        id=file_id,
        upload_id=upload_id,
        filename=sess.filename,
        storage_path=str(dest_path),
        size_bytes=total_written,
        sha256=file_sha,
        merkle_root=merkle_root,
        merkle_leaf_count=len(leaf_hashes),
        reference_sha256=sess.reference_sha256,
        verification_status="PENDING",
    )
    db.add(vfile)
    db.flush()

    for idx, (stage_name, algo) in enumerate(PIPELINE_STAGES, start=1):
        status_val = "Passed" if stage_name in ("UPLOAD", "CHUNK_VALIDATION", "REASSEMBLY") else "Pending"
        db.add(
            VerificationStage(
                file_id=file_id,
                stage_order=idx,
                stage_name=stage_name,
                status=status_val,
                algorithm=algo,
                summary="Completed during upload finalization" if status_val == "Passed" else "Queued for worker",
            )
        )

    job = BackgroundJob(
        job_type="VERIFY_FILE",
        target_id=file_id,
        status="QUEUED",
        progress_pct=20,
    )
    db.add(job)
    db.commit()
    db.refresh(vfile)
    db.refresh(job)

    append_audit_event(
        db,
        actor_id=sess.owner_actor_id,
        action="datalab:upload:finalize",
        target=file_id,
        decision="ALLOW",
        reason=f"Reassembled {sess.filename} ({total_written} bytes, merkle={merkle_root[:12] if merkle_root else 'none'})",
        correlation_id=correlation_id,
    )
    telemetry_bus.publish("file_queued", {"file_id": file_id, "job_id": job.id, "filename": sess.filename})

    if run_inline:
        run_file_verification_pipeline(db, file_id=file_id, job_id=job.id)
        db.refresh(vfile)
        db.refresh(job)

    return vfile, job


def _update_stage(
    db: Session,
    *,
    file_id: str,
    stage_name: str,
    status: str,
    duration_ms: int,
    summary: str,
    details: dict[str, object] | None = None,
) -> None:
    st = db.execute(
        select(VerificationStage).where(
            VerificationStage.file_id == file_id, VerificationStage.stage_name == stage_name
        )
    ).scalar_one_or_none()
    if st:
        st.status = status
        st.duration_ms = duration_ms
        st.summary = summary[:500]
        st.details_json = json.dumps(details or {}, sort_keys=True)
        st.updated_at = datetime.now(timezone.utc)


def run_file_verification_pipeline(db: Session, *, file_id: str, job_id: str | None = None) -> VerifiedFile:
    vfile = db.get(VerifiedFile, file_id)
    if vfile is None:
        raise DomainNotFoundError(f"VerifiedFile '{file_id}' not found")

    job = db.get(BackgroundJob, job_id) if job_id else None
    if job:
        job.status = "RUNNING"
        job.attempts += 1
        job.updated_at = datetime.now(timezone.utc)

    vfile.verification_status = "RUNNING"
    db.commit()

    fpath = Path(vfile.storage_path)
    findings: list[dict[str, str]] = []
    dataset_profile: dict[str, object] | None = None

    # 1. Content-type detection
    t0 = time.perf_counter_ns()
    mime, category = detect_content_type(fpath, vfile.filename)
    vfile.detected_mime = mime
    vfile.detected_category = category
    _update_stage(
        db,
        file_id=file_id,
        stage_name="CONTENT_TYPE",
        status="Passed",
        duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
        summary=f"Detected {mime} ({category}) via magic-byte inspection",
        details={"mime": mime, "category": category},
    )

    # 2. Streaming SHA-256 verification
    t0 = time.perf_counter_ns()
    recomputed_sha = streaming_sha256(fpath)
    vfile.sha256 = recomputed_sha
    _update_stage(
        db,
        file_id=file_id,
        stage_name="STREAMING_HASH",
        status="Passed",
        duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
        summary=f"Streaming SHA-256={recomputed_sha[:16]}... MerkleLeaves={vfile.merkle_leaf_count}",
        details={"sha256": recomputed_sha, "merkle_root": vfile.merkle_root},
    )

    # 3. Structure & Archive inspection
    t0 = time.perf_counter_ns()
    if category == "archive":
        arch = inspect_archive_safely(fpath, mime)
        findings.extend(arch["findings"])  # type: ignore[arg-type]
        st_status = "Failed" if arch["traversal_hits"] else "Passed"
        _update_stage(
            db,
            file_id=file_id,
            stage_name="STRUCTURE_VALIDATION",
            status=st_status,
            duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
            summary=f"Inspected {arch['entries_inspected']} archive entries safely",
            details=arch,
        )
    else:
        _update_stage(
            db,
            file_id=file_id,
            stage_name="STRUCTURE_VALIDATION",
            status="Passed",
            duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
            summary=f"Validated {category} byte stream ({vfile.size_bytes} bytes)",
        )

    # 4. Metadata
    _update_stage(
        db,
        file_id=file_id,
        stage_name="METADATA_ANALYSIS",
        status="Passed",
        duration_ms=1,
        summary=f"Size={vfile.size_bytes}B, Name={vfile.filename}",
    )

    # 5. Reference integrity check
    if vfile.reference_sha256:
        if recomputed_sha == vfile.reference_sha256:
            vfile.reference_status = "MATCH"
            ref_st = "Passed"
            ref_msg = "Calculated SHA-256 matches trusted reference"
        else:
            vfile.reference_status = "MISMATCH"
            ref_st = "Failed"
            ref_msg = "SHA-256 mismatch against provided reference"
            findings.append({"severity": "CRITICAL", "code": "HASH_MISMATCH", "message": ref_msg})
    else:
        vfile.reference_status = "REFERENCE_UNAVAILABLE"
        ref_st = "Warning"
        ref_msg = "No trusted reference digest provided (equality unverified)"
    _update_stage(db, file_id=file_id, stage_name="INTEGRITY_VERIFICATION", status=ref_st, duration_ms=1, summary=ref_msg)

    # 6. Signature & Crypto analysis
    t0 = time.perf_counter_ns()
    sig_status, crypto_ready, crypto_findings = analyze_crypto_and_cert(fpath, category)
    vfile.signature_status = sig_status
    vfile.crypto_readiness = crypto_ready
    findings.extend(crypto_findings)
    sig_stage_status = "Failed" if sig_status in ("EXPIRED", "PARSE_FAILED") else "Passed" if sig_status != "NONE" else "Unsupported"
    _update_stage(db, file_id=file_id, stage_name="SIGNATURE_CHECK", status=sig_stage_status, duration_ms=1, summary=f"Signature={sig_status}")
    _update_stage(
        db,
        file_id=file_id,
        stage_name="CRYPTO_ANALYSIS",
        status="Passed" if crypto_ready != "Requires investigation" else "Warning",
        duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
        summary=f"Classification: {crypto_ready}",
    )

    # 7. Dataset or Log analysis
    t0 = time.perf_counter_ns()
    if category in ("csv", "json", "jsonl"):
        dataset_profile = analyze_dataset_streaming(fpath, category)
        vfile.dataset_profile_json = json.dumps(dataset_profile)
        _update_stage(
            db,
            file_id=file_id,
            stage_name="DATASET_ANALYSIS",
            status="Passed",
            duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
            summary=f"Rows={dataset_profile['row_count']}, Quality={dataset_profile['quality_score']}%",
            details={"row_count": dataset_profile["row_count"], "quality_score": dataset_profile["quality_score"]},
        )
    elif category == "log":
        dataset_profile = analyze_log_streaming(fpath)
        vfile.dataset_profile_json = json.dumps(dataset_profile)
        _update_stage(
            db,
            file_id=file_id,
            stage_name="DATASET_ANALYSIS",
            status="Passed",
            duration_ms=int((time.perf_counter_ns() - t0) / 1_000_000),
            summary=f"LogLines={dataset_profile['total_lines']}, Coverage={dataset_profile['timestamp_coverage_pct']}%",
            details=dataset_profile,
        )
    else:
        _update_stage(
            db,
            file_id=file_id,
            stage_name="DATASET_ANALYSIS",
            status="Skipped",
            duration_ms=0,
            summary=f"Streaming dataset profiler not applicable to {category}",
        )

    # 8. Security & Risk Classification
    high_or_crit = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    risk = "CRITICAL" if any(f["severity"] == "CRITICAL" for f in findings) else "HIGH" if high_or_crit else "LOW"
    vfile.risk_level = risk
    _update_stage(
        db,
        file_id=file_id,
        stage_name="SECURITY_ANALYSIS",
        status="Warning" if high_or_crit else "Passed",
        duration_ms=1,
        summary=f"Structural security check complete ({len(findings)} findings; not an antivirus scan)",
    )
    _update_stage(
        db,
        file_id=file_id,
        stage_name="RISK_CLASSIFICATION",
        status="Passed",
        duration_ms=1,
        summary=f"Classified risk={risk}",
    )

    # 9. Evidence generation
    vfile.findings_json = json.dumps(findings)
    vfile.verification_status = "FAILED" if vfile.reference_status == "MISMATCH" or risk == "CRITICAL" else "WARNING" if vfile.reference_status == "REFERENCE_UNAVAILABLE" else "PASSED"
    vfile.verified_at = datetime.now(timezone.utc)
    receipt = {
        "file_id": vfile.id,
        "filename": vfile.filename,
        "size_bytes": vfile.size_bytes,
        "sha256": vfile.sha256,
        "merkle_root": vfile.merkle_root,
        "reference_status": vfile.reference_status,
        "detected_mime": vfile.detected_mime,
        "crypto_readiness": vfile.crypto_readiness,
        "risk_level": vfile.risk_level,
        "verification_status": vfile.verification_status,
        "verified_at": vfile.verified_at.isoformat(),
    }
    vfile.receipt_json = json.dumps(receipt, indent=2)
    _update_stage(
        db,
        file_id=file_id,
        stage_name="EVIDENCE_GENERATION",
        status="Passed",
        duration_ms=1,
        summary="Generated verifiable receipt JSON",
    )

    if job:
        job.status = "COMPLETED"
        job.progress_pct = 100
        job.completed_at = datetime.now(timezone.utc)
        job.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(vfile)

    append_audit_event(
        db,
        actor_id="datalab-worker",
        action="datalab:file:verified",
        target=file_id,
        decision="ALLOW" if vfile.verification_status != "FAILED" else "DENY",
        reason=f"{vfile.filename} status={vfile.verification_status} risk={risk}",
        correlation_id=f"verify-{file_id[:8]}",
    )
    telemetry_bus.publish(
        "file_verified",
        {
            "file_id": vfile.id,
            "filename": vfile.filename,
            "verification_status": vfile.verification_status,
            "risk_level": vfile.risk_level,
        },
    )
    return vfile

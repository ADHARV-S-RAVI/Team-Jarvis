"""API routes for GB-Scale Data Verification Lab, 24/7 Jobs, System Health, and SSE Telemetry."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import time

from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
import psutil
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.datalab.service import (
    finalize_upload,
    initiate_upload,
    set_upload_state,
    store_upload_chunk,
)
from backend.app.datalab.worker import background_worker
from backend.app.db.models import (
    BackgroundJob,
    UploadChunk,
    UploadSession,
    VerificationStage,
    VerifiedFile,
)
from backend.app.db.session import get_db
from backend.app.services.foundation_service import DomainNotFoundError, DomainValidationError
from backend.app.telemetry.bus import telemetry_bus

datalab_router = APIRouter()
_PROC_START = time.monotonic()


class UploadInitRequest(BaseModel):
    filename: str
    declared_size_bytes: int
    chunk_size_bytes: int = 1024 * 1024
    reference_sha256: str | None = None
    owner_actor_id: str = "secop"


class VerifyReferenceRequest(BaseModel):
    reference_sha256: str


@datalab_router.post("/datalab/uploads/init", status_code=201, tags=["datalab"])
def init_upload_endpoint(
    payload: UploadInitRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    sess = initiate_upload(
        db,
        filename=payload.filename,
        declared_size_bytes=payload.declared_size_bytes,
        chunk_size_bytes=payload.chunk_size_bytes,
        reference_sha256=payload.reference_sha256,
        owner_actor_id=payload.owner_actor_id,
        correlation_id=getattr(request.state, "correlation_id", "datalab-init"),
    )
    return {
        "upload_id": sess.id,
        "filename": sess.filename,
        "declared_size_bytes": sess.declared_size_bytes,
        "chunk_size_bytes": sess.chunk_size_bytes,
        "total_chunks": sess.total_chunks,
        "status": sess.status,
    }


@datalab_router.get("/datalab/uploads/{upload_id}", tags=["datalab"])
def get_upload_status_endpoint(upload_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    sess = db.get(UploadSession, upload_id)
    if sess is None:
        raise DomainNotFoundError(f"Upload session '{upload_id}' not found")
    chunks = list(
        db.execute(
            select(UploadChunk)
            .where(UploadChunk.upload_id == upload_id)
            .order_by(UploadChunk.chunk_index.asc())
        )
        .scalars()
        .all()
    )
    return {
        "upload_id": sess.id,
        "filename": sess.filename,
        "declared_size_bytes": sess.declared_size_bytes,
        "chunk_size_bytes": sess.chunk_size_bytes,
        "total_chunks": sess.total_chunks,
        "received_chunks": sess.received_chunks,
        "status": sess.status,
        "chunks": [
            {
                "chunk_index": c.chunk_index,
                "size_bytes": c.size_bytes,
                "chunk_sha256": c.chunk_sha256,
                "status": c.status,
                "attempts": c.attempts,
            }
            for c in chunks
        ],
    }


@datalab_router.put("/datalab/uploads/{upload_id}/chunks/{chunk_index}", tags=["datalab"])
async def upload_chunk_endpoint(
    upload_id: str,
    chunk_index: int,
    request: Request,
    x_chunk_sha256: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    body = await request.body()
    rec = store_upload_chunk(
        db,
        upload_id=upload_id,
        chunk_index=chunk_index,
        chunk_bytes=body,
        expected_sha256=x_chunk_sha256,
    )
    return {
        "upload_id": upload_id,
        "chunk_index": rec.chunk_index,
        "size_bytes": rec.size_bytes,
        "chunk_sha256": rec.chunk_sha256,
        "status": rec.status,
    }


@datalab_router.post("/datalab/uploads/{upload_id}/pause", tags=["datalab"])
def pause_upload_endpoint(upload_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    sess = set_upload_state(db, upload_id=upload_id, new_status="PAUSED")
    return {"upload_id": sess.id, "status": sess.status}


@datalab_router.post("/datalab/uploads/{upload_id}/resume", tags=["datalab"])
def resume_upload_endpoint(upload_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    sess = set_upload_state(db, upload_id=upload_id, new_status="UPLOADING")
    return {"upload_id": sess.id, "status": sess.status}


@datalab_router.post("/datalab/uploads/{upload_id}/cancel", tags=["datalab"])
def cancel_upload_endpoint(upload_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    sess = set_upload_state(db, upload_id=upload_id, new_status="CANCELLED")
    return {"upload_id": sess.id, "status": sess.status}


@datalab_router.post("/datalab/uploads/{upload_id}/finalize", tags=["datalab"])
def finalize_upload_endpoint(
    upload_id: str,
    request: Request,
    inline: bool = Query(default=False),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    vfile, job = finalize_upload(
        db,
        upload_id=upload_id,
        run_inline=inline,
        correlation_id=getattr(request.state, "correlation_id", "datalab-finalize"),
    )
    return {
        "file_id": vfile.id,
        "job_id": job.id,
        "filename": vfile.filename,
        "size_bytes": vfile.size_bytes,
        "sha256": vfile.sha256,
        "merkle_root": vfile.merkle_root,
        "verification_status": vfile.verification_status,
        "job_status": job.status,
    }


@datalab_router.get("/datalab/files", tags=["datalab"])
def list_verified_files_endpoint(
    risk_level: str | None = None,
    status_filter: str | None = None,
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    q = select(VerifiedFile).order_by(VerifiedFile.created_at.desc())
    if risk_level:
        q = q.where(VerifiedFile.risk_level == risk_level)
    if status_filter:
        q = q.where(VerifiedFile.verification_status == status_filter)
    files = list(db.execute(q).scalars().all())
    return [
        {
            "id": f.id,
            "filename": f.filename,
            "size_bytes": f.size_bytes,
            "detected_mime": f.detected_mime,
            "detected_category": f.detected_category,
            "sha256": f.sha256,
            "merkle_root": f.merkle_root,
            "merkle_leaf_count": f.merkle_leaf_count,
            "reference_status": f.reference_status,
            "signature_status": f.signature_status,
            "crypto_readiness": f.crypto_readiness,
            "risk_level": f.risk_level,
            "verification_status": f.verification_status,
            "created_at": f.created_at.isoformat(),
            "verified_at": f.verified_at.isoformat() if f.verified_at else None,
        }
        for f in files
    ]


@datalab_router.get("/datalab/files/{file_id}", tags=["datalab"])
def get_verified_file_detail_endpoint(file_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    f = db.get(VerifiedFile, file_id)
    if f is None:
        raise DomainNotFoundError(f"File '{file_id}' not found")
    stages = list(
        db.execute(
            select(VerificationStage)
            .where(VerificationStage.file_id == file_id)
            .order_by(VerificationStage.stage_order.asc())
        )
        .scalars()
        .all()
    )
    return {
        "id": f.id,
        "upload_id": f.upload_id,
        "filename": f.filename,
        "size_bytes": f.size_bytes,
        "detected_mime": f.detected_mime,
        "detected_category": f.detected_category,
        "sha256": f.sha256,
        "merkle_root": f.merkle_root,
        "merkle_leaf_count": f.merkle_leaf_count,
        "reference_sha256": f.reference_sha256,
        "reference_status": f.reference_status,
        "signature_status": f.signature_status,
        "crypto_readiness": f.crypto_readiness,
        "risk_level": f.risk_level,
        "verification_status": f.verification_status,
        "dataset_profile": json.loads(f.dataset_profile_json) if f.dataset_profile_json else None,
        "findings": json.loads(f.findings_json or "[]"),
        "receipt": json.loads(f.receipt_json) if f.receipt_json else None,
        "created_at": f.created_at.isoformat(),
        "verified_at": f.verified_at.isoformat() if f.verified_at else None,
        "stages": [
            {
                "stage_order": s.stage_order,
                "stage_name": s.stage_name,
                "status": s.status,
                "duration_ms": s.duration_ms,
                "algorithm": s.algorithm,
                "summary": s.summary,
                "details": json.loads(s.details_json or "{}"),
            }
            for s in stages
        ],
    }


@datalab_router.post("/datalab/files/{file_id}/verify-reference", tags=["datalab"])
def verify_file_reference_endpoint(
    file_id: str,
    payload: VerifyReferenceRequest,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    f = db.get(VerifiedFile, file_id)
    if f is None:
        raise DomainNotFoundError(f"File '{file_id}' not found")
    ref = payload.reference_sha256.strip().lower()
    f.reference_sha256 = ref
    if f.sha256 == ref:
        f.reference_status = "MATCH"
        if f.verification_status == "WARNING":
            f.verification_status = "PASSED"
    else:
        f.reference_status = "MISMATCH"
        f.verification_status = "FAILED"
        f.risk_level = "CRITICAL"
    db.commit()
    return {"file_id": f.id, "reference_status": f.reference_status, "verification_status": f.verification_status}


@datalab_router.get("/datalab/files/{file_id}/report", tags=["datalab"])
def export_file_report_endpoint(file_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    detail = get_verified_file_detail_endpoint(file_id, db)
    return JSONResponse(content=detail)


@datalab_router.get("/jobs", tags=["jobs"])
def list_jobs_endpoint(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    jobs = list(db.execute(select(BackgroundJob).order_by(BackgroundJob.created_at.desc()).limit(100)).scalars().all())
    return [
        {
            "id": j.id,
            "job_type": j.job_type,
            "target_id": j.target_id,
            "status": j.status,
            "progress_pct": j.progress_pct,
            "attempts": j.attempts,
            "error_message": j.error_message,
            "created_at": j.created_at.isoformat(),
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }
        for j in jobs
    ]


@datalab_router.post("/jobs/{job_id}/retry", tags=["jobs"])
def retry_job_endpoint(job_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    job = db.get(BackgroundJob, job_id)
    if job is None:
        raise DomainNotFoundError(f"Job '{job_id}' not found")
    job.status = "QUEUED"
    job.error_message = None
    job.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": job.id, "status": job.status}


@datalab_router.post("/jobs/{job_id}/cancel", tags=["jobs"])
def cancel_job_endpoint(job_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    job = db.get(BackgroundJob, job_id)
    if job is None:
        raise DomainNotFoundError(f"Job '{job_id}' not found")
    if job.status in ("COMPLETED", "FAILED"):
        raise DomainValidationError(f"Cannot cancel job in status {job.status}")
    job.status = "CANCELLED"
    job.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": job.id, "status": job.status}


@datalab_router.get("/health/live", tags=["system"])
def health_live_endpoint() -> dict[str, object]:
    return {"status": "alive", "uptime_seconds": round(time.monotonic() - _PROC_START, 2)}


@datalab_router.get("/health/ready", tags=["system"])
def health_ready_endpoint(db: Session = Depends(get_db)) -> dict[str, object]:
    db.execute(text("SELECT 1"))
    return {
        "status": "ready",
        "database": "ok",
        "worker_running": background_worker.is_running,
    }


@datalab_router.get("/system/metrics", tags=["system"])
def system_metrics_endpoint(db: Session = Depends(get_db)) -> dict[str, object]:
    settings = get_settings()
    proc = psutil.Process(os.getpid())
    disk = shutil.disk_usage(Path.cwd())
    queue_depth = db.execute(
        select(func.count(BackgroundJob.id)).where(BackgroundJob.status.in_(("QUEUED", "RUNNING", "RETRYING")))
    ).scalar_one()
    failed_jobs = db.execute(
        select(func.count(BackgroundJob.id)).where(BackgroundJob.status == "FAILED")
    ).scalar_one()
    storage_used = db.execute(select(func.coalesce(func.sum(VerifiedFile.size_bytes), 0))).scalar_one()
    files_count = db.execute(select(func.count(VerifiedFile.id))).scalar_one()

    return {
        "uptime_seconds": round(time.monotonic() - _PROC_START, 2),
        "worker_running": background_worker.is_running,
        "worker_uptime_seconds": background_worker.uptime_seconds,
        "cpu_percent": psutil.cpu_percent(interval=None),
        "process_rss_mb": round(proc.memory_info().rss / (1024 * 1024), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_used_pct": round((disk.used / max(1, disk.total)) * 100, 1),
        "queue_depth": int(queue_depth or 0),
        "failed_jobs": int(failed_jobs or 0),
        "files_verified_count": int(files_count or 0),
        "storage_used_bytes": int(storage_used or 0),
        "storage_quota_bytes": settings.storage_quota_bytes,
        "max_upload_bytes": settings.max_upload_bytes,
    }


@datalab_router.get("/telemetry/stream", tags=["telemetry"])
async def telemetry_stream_endpoint(request: Request) -> StreamingResponse:
    loop = asyncio.get_running_loop()
    q = telemetry_bus.subscribe(loop)

    async def event_gen():
        try:
            for item in telemetry_bus.recent(10):
                yield f"id: {item['id']}\nevent: {item['type']}\ndata: {json.dumps(item)}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=10.0)
                    yield f"id: {evt['id']}\nevent: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
                except asyncio.TimeoutError:
                    hb = {"timestamp": datetime.now(timezone.utc).isoformat(), "worker": background_worker.is_running}
                    yield f"event: heartbeat\ndata: {json.dumps(hb)}\n\n"
        finally:
            telemetry_bus.unsubscribe(loop, q)

    return StreamingResponse(event_gen(), media_type="text/event-stream")

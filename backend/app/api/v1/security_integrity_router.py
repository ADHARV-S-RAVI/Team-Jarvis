"""API routes for Stage 13 Identity Assurance Center, File Integrity Monitoring, and Unified Security Center."""

from __future__ import annotations

from datetime import datetime, timezone
import json

from fastapi import APIRouter, Depends, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import (
    AuditEvent,
    BaselineChangeRequest,
    IdentityCredential,
    IdentityVerificationEvent,
    Incident,
    IntegrityFinding,
    IntegrityManifest,
    IntegrityManifestEntry,
    IntegrityScan,
    WebAuthnChallenge,
)
from backend.app.db.session import get_db
from backend.app.identity_assurance.service import (
    generate_authenticate_options,
    generate_register_options,
    get_or_init_policy,
    has_fresh_assurance,
    record_admin_recovery,
    record_camera_demo_event,
    revoke_or_remove_credential,
    update_policy,
    verify_authentication,
    verify_registration,
)
from backend.app.integrity.service import (
    approve_or_reject_baseline_change,
    get_active_manifest,
    initialize_baseline,
    record_user_selected_scan,
    request_baseline_update,
    run_application_scan,
    verify_manifest_integrity,
)
from backend.app.services.foundation_service import DomainNotFoundError

security_integrity_router = APIRouter()


def _cid(request: Request) -> str:
    return getattr(request.state, "correlation_id", "stage13-req")


class RegisterOptionsReq(BaseModel):
    actor_id: str
    rp_id: str = "localhost"


class RegisterVerifyReq(BaseModel):
    actor_id: str
    challenge_id: str
    credential: dict[str, object]
    device_id: str | None = None
    rp_id: str = "localhost"
    origin: str = "http://localhost:5173"


class AuthOptionsReq(BaseModel):
    actor_id: str
    rp_id: str = "localhost"


class AuthVerifyReq(BaseModel):
    actor_id: str
    challenge_id: str
    credential: dict[str, object]
    rp_id: str = "localhost"
    origin: str = "http://localhost:5173"


class CredentialRevokeReq(BaseModel):
    actor_id: str
    reason: str = Field(min_length=1)


class PolicyUpdateReq(BaseModel):
    operator_actor_id: str
    policy_mode: str
    freshness_window_seconds: int
    require_user_verification: bool = True


class AdminRecoveryReq(BaseModel):
    operator_actor_id: str
    target_actor_id: str
    reason: str = Field(min_length=1)


class CameraDemoEventReq(BaseModel):
    actor_id: str
    state: str


class BaselineInitReq(BaseModel):
    operator_actor_id: str = "secop"


class ApplicationScanReq(BaseModel):
    actor_id: str = "secop"
    max_duration_seconds: float = 30.0


class UserSelectedScanReq(BaseModel):
    actor_id: str = "secop"
    entries: list[dict[str, object]]


class BaselineChangeReqBody(BaseModel):
    requested_by: str
    reason: str
    scan_id: str | None = None


class BaselineResolveReq(BaseModel):
    operator_actor_id: str


# ========================
# Identity Assurance Routes
# ========================


@security_integrity_router.get("/identity-assurance/status", tags=["identity-assurance"])
def identity_assurance_status_endpoint(
    actor_id: str = "alice", db: Session = Depends(get_db)
) -> dict[str, object]:
    policy = get_or_init_policy(db)
    fresh, latest_ev = has_fresh_assurance(db, actor_id)
    active_creds = db.execute(
        select(func.count(IdentityCredential.id)).where(IdentityCredential.credential_status == "ACTIVE")
    ).scalar_one()
    revoked_creds = db.execute(
        select(func.count(IdentityCredential.id)).where(IdentityCredential.credential_status == "REVOKED")
    ).scalar_one()
    success_events = db.execute(
        select(func.count(IdentityVerificationEvent.id)).where(IdentityVerificationEvent.verification_status == "SUCCESS")
    ).scalar_one()
    failed_events = db.execute(
        select(func.count(IdentityVerificationEvent.id)).where(
            IdentityVerificationEvent.verification_status.in_(("FAILED", "REVOKED_REJECTED"))
        )
    ).scalar_one()
    now = datetime.now(timezone.utc)
    expired_challenges = db.execute(
        select(func.count(WebAuthnChallenge.id)).where(
            WebAuthnChallenge.consumed_at.is_(None), WebAuthnChallenge.expires_at <= now
        )
    ).scalar_one()

    return {
        "actor_id": actor_id,
        "assurance_level": latest_ev.assurance_level if fresh and latest_ev else "STANDARD_SESSION",
        "fresh_verified": fresh,
        "fresh_until": latest_ev.fresh_until.isoformat() if latest_ev and latest_ev.fresh_until else None,
        "latest_verification_at": latest_ev.created_at.isoformat() if latest_ev else None,
        "policy": {
            "policy_mode": policy.policy_mode,
            "freshness_window_seconds": policy.freshness_window_seconds,
            "require_user_verification": policy.require_user_verification,
            "updated_by": policy.updated_by,
        },
        "counts": {
            "total_enrolled_credentials": int(active_creds or 0),
            "revoked_credentials": int(revoked_creds or 0),
            "successful_verifications": int(success_events or 0),
            "failed_verifications": int(failed_events or 0),
            "expired_challenges": int(expired_challenges or 0),
        },
    }


@security_integrity_router.get("/identity-assurance/credentials", tags=["identity-assurance"])
def list_credentials_endpoint(actor_id: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    q = select(IdentityCredential).order_by(IdentityCredential.created_at.desc())
    if actor_id:
        q = q.where(IdentityCredential.actor_id == actor_id)
    rows = list(db.execute(q).scalars().all())
    return [
        {
            "id": r.id,
            "actor_id": r.actor_id,
            "device_id": r.device_id,
            "credential_id": r.credential_id,
            "sign_count": r.sign_count,
            "metadata": json.loads(r.authenticator_metadata or "{}"),
            "credential_status": r.credential_status,
            "created_at": r.created_at.isoformat(),
            "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
            "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
        }
        for r in rows
    ]


@security_integrity_router.post("/identity-assurance/register/options", tags=["identity-assurance"])
def register_options_endpoint(payload: RegisterOptionsReq, db: Session = Depends(get_db)) -> dict[str, object]:
    return generate_register_options(db, actor_id=payload.actor_id, rp_id=payload.rp_id)


@security_integrity_router.post("/identity-assurance/register/verify", status_code=status.HTTP_201_CREATED, tags=["identity-assurance"])
def register_verify_endpoint(
    payload: RegisterVerifyReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    cred = verify_registration(
        db,
        actor_id=payload.actor_id,
        challenge_id=payload.challenge_id,
        credential_json=payload.credential,
        device_id=payload.device_id,
        rp_id=payload.rp_id,
        origin=payload.origin,
        correlation_id=_cid(request),
    )
    return {
        "status": "IDENTITY CREDENTIAL REGISTERED",
        "id": cred.id,
        "credential_id": cred.credential_id,
        "actor_id": cred.actor_id,
        "device_id": cred.device_id,
    }


@security_integrity_router.post("/identity-assurance/authenticate/options", tags=["identity-assurance"])
def auth_options_endpoint(payload: AuthOptionsReq, db: Session = Depends(get_db)) -> dict[str, object]:
    return generate_authenticate_options(db, actor_id=payload.actor_id, rp_id=payload.rp_id)


@security_integrity_router.post("/identity-assurance/authenticate/verify", tags=["identity-assurance"])
def auth_verify_endpoint(
    payload: AuthVerifyReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    ev = verify_authentication(
        db,
        actor_id=payload.actor_id,
        challenge_id=payload.challenge_id,
        credential_json=payload.credential,
        rp_id=payload.rp_id,
        origin=payload.origin,
        correlation_id=_cid(request),
    )
    return {
        "verification_status": ev.verification_status,
        "assurance_level": ev.assurance_level,
        "fresh_until": ev.fresh_until.isoformat() if ev.fresh_until else None,
        "event_id": ev.id,
    }


@security_integrity_router.post("/identity-assurance/credentials/{credential_record_id}/revoke", tags=["identity-assurance"])
def revoke_credential_endpoint(
    credential_record_id: str,
    payload: CredentialRevokeReq,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return revoke_or_remove_credential(
        db,
        credential_record_id=credential_record_id,
        actor_id=payload.actor_id,
        reason=payload.reason,
        delete_record=False,
        correlation_id=_cid(request),
    )


@security_integrity_router.delete("/identity-assurance/credentials/{credential_record_id}", tags=["identity-assurance"])
def delete_credential_endpoint(
    credential_record_id: str,
    actor_id: str = "secop",
    reason: str = "Operator credential removal",
    request: Request = None,  # type: ignore[assignment]
    db: Session = Depends(get_db),
) -> dict[str, object]:
    return revoke_or_remove_credential(
        db,
        credential_record_id=credential_record_id,
        actor_id=actor_id,
        reason=reason,
        delete_record=True,
        correlation_id=_cid(request) if request else "cred-del",
    )


@security_integrity_router.get("/identity-assurance/history", tags=["identity-assurance"])
def verification_history_endpoint(actor_id: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    q = select(IdentityVerificationEvent).order_by(IdentityVerificationEvent.created_at.desc()).limit(100)
    if actor_id:
        q = q.where(IdentityVerificationEvent.actor_id == actor_id)
    rows = list(db.execute(q).scalars().all())
    return [
        {
            "id": r.id,
            "actor_id": r.actor_id,
            "credential_id": r.credential_id,
            "device_id": r.device_id,
            "verification_method": r.verification_method,
            "verification_status": r.verification_status,
            "assurance_level": r.assurance_level,
            "fresh_until": r.fresh_until.isoformat() if r.fresh_until else None,
            "reason": r.reason,
            "correlation_id": r.correlation_id,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@security_integrity_router.get("/identity-assurance/policy", tags=["identity-assurance"])
def get_policy_endpoint(db: Session = Depends(get_db)) -> dict[str, object]:
    p = get_or_init_policy(db)
    return {
        "policy_mode": p.policy_mode,
        "freshness_window_seconds": p.freshness_window_seconds,
        "require_user_verification": p.require_user_verification,
        "updated_by": p.updated_by,
        "updated_at": p.updated_at.isoformat(),
    }


@security_integrity_router.put("/identity-assurance/policy", tags=["identity-assurance"])
def put_policy_endpoint(
    payload: PolicyUpdateReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    p = update_policy(
        db,
        operator_actor_id=payload.operator_actor_id,
        policy_mode=payload.policy_mode,
        freshness_window_seconds=payload.freshness_window_seconds,
        require_user_verification=payload.require_user_verification,
        correlation_id=_cid(request),
    )
    return {
        "policy_mode": p.policy_mode,
        "freshness_window_seconds": p.freshness_window_seconds,
        "require_user_verification": p.require_user_verification,
        "updated_by": p.updated_by,
    }


@security_integrity_router.post("/identity-assurance/recovery", tags=["identity-assurance"])
def recovery_endpoint(
    payload: AdminRecoveryReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    ev = record_admin_recovery(
        db,
        operator_actor_id=payload.operator_actor_id,
        target_actor_id=payload.target_actor_id,
        reason=payload.reason,
        correlation_id=_cid(request),
    )
    return {"event_id": ev.id, "assurance_level": ev.assurance_level, "fresh_until": ev.fresh_until.isoformat() if ev.fresh_until else None}


@security_integrity_router.post("/identity-assurance/camera-demo/event", tags=["identity-assurance"])
def camera_demo_event_endpoint(
    payload: CameraDemoEventReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, str]:
    record_camera_demo_event(db, actor_id=payload.actor_id, state=payload.state, correlation_id=_cid(request))
    return {"status": payload.state, "note": "Non-authenticating camera demo logged; zero media stored."}


# =============================
# File Integrity Intelligence
# =============================


@security_integrity_router.get("/integrity/status", tags=["integrity"])
def integrity_status_endpoint(db: Session = Depends(get_db)) -> dict[str, object]:
    manifest = get_active_manifest(db)
    latest_scan = db.execute(
        select(IntegrityScan).order_by(IntegrityScan.started_at.desc()).limit(1)
    ).scalar_one_or_none()
    pending_reqs = db.execute(
        select(func.count(BaselineChangeRequest.id)).where(BaselineChangeRequest.status == "PENDING")
    ).scalar_one()
    return {
        "baseline_status": manifest.status if manifest else "BASELINE_UNAVAILABLE",
        "manifest_id": manifest.id if manifest else None,
        "manifest_version": manifest.manifest_version if manifest else None,
        "manifest_root_hash": manifest.root_hash if manifest else None,
        "pending_change_requests": int(pending_reqs or 0),
        "latest_scan": {
            "id": latest_scan.id,
            "scan_scope": latest_scan.scan_scope,
            "scan_status": latest_scan.scan_status,
            "files_scanned": latest_scan.files_scanned,
            "files_verified": latest_scan.files_verified,
            "files_modified": latest_scan.files_modified,
            "files_missing": latest_scan.files_missing,
            "files_unexpected": latest_scan.files_unexpected,
            "files_unreadable": latest_scan.files_unreadable,
            "duration_ms": latest_scan.duration_ms,
            "started_at": latest_scan.started_at.isoformat(),
        }
        if latest_scan
        else None,
    }


@security_integrity_router.post("/integrity/baseline/initialize", status_code=status.HTTP_201_CREATED, tags=["integrity"])
def init_baseline_endpoint(
    payload: BaselineInitReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    m = initialize_baseline(db, operator_actor_id=payload.operator_actor_id, correlation_id=_cid(request))
    return {
        "manifest_id": m.id,
        "manifest_version": m.manifest_version,
        "root_hash": m.root_hash,
        "status": m.status,
    }


@security_integrity_router.get("/integrity/baseline", tags=["integrity"])
def get_baseline_endpoint(db: Session = Depends(get_db)) -> dict[str, object]:
    m = get_active_manifest(db)
    if m is None:
        return {"status": "BASELINE_UNAVAILABLE", "entries": []}
    entries = list(
        db.execute(
            select(IntegrityManifestEntry)
            .where(IntegrityManifestEntry.manifest_id == m.id)
            .order_by(IntegrityManifestEntry.relative_path.asc())
        )
        .scalars()
        .all()
    )
    return {
        "id": m.id,
        "manifest_version": m.manifest_version,
        "root_hash": m.root_hash,
        "status": m.status,
        "created_by": m.created_by,
        "created_at": m.created_at.isoformat(),
        "entry_count": len(entries),
        "entries": [
            {
                "relative_path": e.relative_path,
                "sha256_hash": e.sha256_hash,
                "file_size": e.file_size,
                "file_type": e.file_type,
                "baseline_status": e.baseline_status,
            }
            for e in entries[:500]
        ],
    }


@security_integrity_router.post("/integrity/baseline/verify", tags=["integrity"])
def verify_baseline_endpoint(request: Request, db: Session = Depends(get_db)) -> dict[str, object]:
    return verify_manifest_integrity(db, correlation_id=_cid(request))


@security_integrity_router.get("/integrity/baseline/change-requests", tags=["integrity"])
def list_baseline_changes_endpoint(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    rows = list(db.execute(select(BaselineChangeRequest).order_by(BaselineChangeRequest.created_at.desc())).scalars().all())
    return [
        {
            "id": r.id,
            "manifest_id": r.manifest_id,
            "requested_by": r.requested_by,
            "reason": r.reason,
            "previous_manifest_hash": r.previous_manifest_hash,
            "new_manifest_hash": r.new_manifest_hash,
            "status": r.status,
            "approved_by": r.approved_by,
            "audit_ref": r.audit_ref,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


@security_integrity_router.post("/integrity/baseline/change-requests", status_code=status.HTTP_201_CREATED, tags=["integrity"])
def create_baseline_change_endpoint(
    payload: BaselineChangeReqBody, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    req = request_baseline_update(
        db,
        requested_by=payload.requested_by,
        reason=payload.reason,
        scan_id=payload.scan_id,
        correlation_id=_cid(request),
    )
    return {"id": req.id, "status": req.status, "manifest_id": req.manifest_id}


@security_integrity_router.post("/integrity/baseline/change-requests/{request_id}/approve", tags=["integrity"])
def approve_baseline_change_endpoint(
    request_id: str, payload: BaselineResolveReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    req = approve_or_reject_baseline_change(
        db,
        request_id=request_id,
        operator_actor_id=payload.operator_actor_id,
        approve=True,
        correlation_id=_cid(request),
    )
    return {"id": req.id, "status": req.status, "audit_ref": req.audit_ref}


@security_integrity_router.post("/integrity/baseline/change-requests/{request_id}/reject", tags=["integrity"])
def reject_baseline_change_endpoint(
    request_id: str, payload: BaselineResolveReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    req = approve_or_reject_baseline_change(
        db,
        request_id=request_id,
        operator_actor_id=payload.operator_actor_id,
        approve=False,
        correlation_id=_cid(request),
    )
    return {"id": req.id, "status": req.status, "audit_ref": req.audit_ref}


@security_integrity_router.post("/integrity/scans", status_code=status.HTTP_201_CREATED, tags=["integrity"])
def run_app_scan_endpoint(
    payload: ApplicationScanReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    s = run_application_scan(
        db,
        actor_id=payload.actor_id,
        max_duration_seconds=payload.max_duration_seconds,
        correlation_id=_cid(request),
    )
    return {
        "scan_id": s.id,
        "scan_status": s.scan_status,
        "files_scanned": s.files_scanned,
        "files_verified": s.files_verified,
        "files_modified": s.files_modified,
        "files_missing": s.files_missing,
        "files_unexpected": s.files_unexpected,
        "duration_ms": s.duration_ms,
    }


@security_integrity_router.post("/integrity/scans/user-selected", status_code=status.HTTP_201_CREATED, tags=["integrity"])
def run_user_selected_scan_endpoint(
    payload: UserSelectedScanReq, request: Request, db: Session = Depends(get_db)
) -> dict[str, object]:
    s = record_user_selected_scan(
        db, actor_id=payload.actor_id, entries=payload.entries, correlation_id=_cid(request)
    )
    return {
        "scan_id": s.id,
        "scan_status": s.scan_status,
        "files_scanned": s.files_scanned,
        "files_verified": s.files_verified,
        "files_modified": s.files_modified,
        "duration_ms": s.duration_ms,
    }


@security_integrity_router.get("/integrity/scans", tags=["integrity"])
def list_scans_endpoint(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    rows = list(db.execute(select(IntegrityScan).order_by(IntegrityScan.started_at.desc()).limit(50)).scalars().all())
    return [
        {
            "id": s.id,
            "manifest_id": s.manifest_id,
            "scan_scope": s.scan_scope,
            "scan_status": s.scan_status,
            "files_scanned": s.files_scanned,
            "files_verified": s.files_verified,
            "files_modified": s.files_modified,
            "files_missing": s.files_missing,
            "files_unexpected": s.files_unexpected,
            "files_unreadable": s.files_unreadable,
            "files_excluded": s.files_excluded,
            "duration_ms": s.duration_ms,
            "started_at": s.started_at.isoformat(),
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
        }
        for s in rows
    ]


@security_integrity_router.get("/integrity/scans/{scan_id}", tags=["integrity"])
def get_scan_endpoint(scan_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    s = db.get(IntegrityScan, scan_id)
    if s is None:
        raise DomainNotFoundError("Scan not found")
    return {
        "id": s.id,
        "scan_scope": s.scan_scope,
        "scan_status": s.scan_status,
        "files_scanned": s.files_scanned,
        "files_verified": s.files_verified,
        "files_modified": s.files_modified,
        "files_missing": s.files_missing,
        "files_unexpected": s.files_unexpected,
        "duration_ms": s.duration_ms,
    }


@security_integrity_router.get("/integrity/scans/{scan_id}/findings", tags=["integrity"])
def get_scan_findings_endpoint(scan_id: str, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    rows = list(
        db.execute(
            select(IntegrityFinding)
            .where(IntegrityFinding.scan_id == scan_id)
            .order_by(IntegrityFinding.severity.desc(), IntegrityFinding.relative_path.asc())
        )
        .scalars()
        .all()
    )
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "relative_path": f.relative_path,
            "file_type": f.file_type,
            "file_size": f.file_size,
            "expected_hash": f.expected_hash,
            "actual_hash": f.actual_hash,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "created_at": f.created_at.isoformat(),
        }
        for f in rows
    ]


@security_integrity_router.post("/integrity/scans/{scan_id}/cancel", tags=["integrity"])
def cancel_scan_endpoint(scan_id: str, db: Session = Depends(get_db)) -> dict[str, object]:
    s = db.get(IntegrityScan, scan_id)
    if s is None:
        raise DomainNotFoundError("Scan not found")
    s.scan_status = "CANCELLED"
    s.completed_at = datetime.now(timezone.utc)
    db.commit()
    return {"id": s.id, "scan_status": s.scan_status}


@security_integrity_router.get("/integrity/findings", tags=["integrity"])
def list_all_findings_endpoint(finding_type: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, object]]:
    q = select(IntegrityFinding).order_by(IntegrityFinding.created_at.desc()).limit(300)
    if finding_type:
        q = q.where(IntegrityFinding.finding_type == finding_type)
    rows = list(db.execute(q).scalars().all())
    return [
        {
            "id": f.id,
            "scan_id": f.scan_id,
            "relative_path": f.relative_path,
            "file_type": f.file_type,
            "file_size": f.file_size,
            "expected_hash": f.expected_hash,
            "actual_hash": f.actual_hash,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "created_at": f.created_at.isoformat(),
        }
        for f in rows
    ]


@security_integrity_router.get("/integrity/history", tags=["integrity"])
def integrity_history_endpoint(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    return list_scans_endpoint(db)


# ==============================
# Unified Security Center Routes
# ==============================


@security_integrity_router.get("/security-integrity/overview", tags=["security-integrity"])
def unified_overview_endpoint(actor_id: str = "alice", db: Session = Depends(get_db)) -> dict[str, object]:
    return {
        "identity": identity_assurance_status_endpoint(actor_id=actor_id, db=db),
        "integrity": integrity_status_endpoint(db=db),
    }


@security_integrity_router.get("/security-integrity/events", tags=["security-integrity"])
def unified_events_endpoint(db: Session = Depends(get_db)) -> list[dict[str, object]]:
    evs = list(
        db.execute(
            select(AuditEvent)
            .where(AuditEvent.action.like("identity:%") | AuditEvent.action.like("integrity:%"))
            .order_by(AuditEvent.sequence.desc())
            .limit(40)
        )
        .scalars()
        .all()
    )
    return [
        {
            "event_id": e.event_id,
            "sequence": e.sequence,
            "timestamp": e.timestamp.isoformat(),
            "actor_id": e.actor_id,
            "action": e.action,
            "target": e.target,
            "decision": e.decision,
            "reason": e.reason,
            "correlation_id": e.correlation_id,
        }
        for e in evs
    ]


@security_integrity_router.get("/security-integrity/health", tags=["security-integrity"])
def unified_health_endpoint(db: Session = Depends(get_db)) -> dict[str, object]:
    open_inc = db.execute(select(func.count(Incident.id)).where(Incident.status == "OPEN")).scalar_one()
    return {
        "status": "ok",
        "open_incidents": int(open_inc or 0),
        "webauthn_library": "webauthn==3.0.1",
        "scanner_version": "1.0.0",
    }

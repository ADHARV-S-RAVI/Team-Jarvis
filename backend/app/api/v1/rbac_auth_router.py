"""API routes for Advanced RBAC Authentication, 256-bit Session Secrets, Protected Files, and Admin Controls."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import secrets
from typing import Literal

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.db.models import Actor, AuditEvent, AuthSession, Device
from backend.app.db.session import get_db
from backend.app.identity_assurance.service import (
    generate_authenticate_options,
    verify_authentication,
)
from backend.app.services.foundation_service import (
    DomainNotFoundError,
    DomainValidationError,
    create_session,
    record_audit_event,
)
from backend.app.services.rbac_auth_service import (
    authenticate_session_request,
    create_protected_file,
    list_accessible_files,
    logout_session,
    mark_session_verified,
    provision_rbac_account,
    read_protected_file,
    role_login,
)

rbac_auth_router = APIRouter()


def _cid(request: Request) -> str:
    return getattr(request.state, "correlation_id", "rbac-req")


def _extract_token(authorization: str | None, x_session_token: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return x_session_token


def _get_auth_context(
    request: Request,
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_session_token: str | None = Header(default=None, alias="X-Session-Token"),
    qshield_session_id: str | None = Cookie(default=None),
    qshield_session_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
    required_roles: set[str] | None = None,
) -> tuple[AuthSession, Actor]:
    sid = x_session_id or qshield_session_id
    token = _extract_token(authorization, x_session_token) or qshield_session_token
    try:
        return authenticate_session_request(
            db,
            session_id=sid,
            session_token=token,
            required_roles=required_roles,
            correlation_id=_cid(request),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


def require_any_role(
    request: Request,
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_session_token: str | None = Header(default=None, alias="X-Session-Token"),
    qshield_session_id: str | None = Cookie(default=None),
    qshield_session_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> tuple[AuthSession, Actor]:
    return _get_auth_context(
        request,
        x_session_id=x_session_id,
        authorization=authorization,
        x_session_token=x_session_token,
        qshield_session_id=qshield_session_id,
        qshield_session_token=qshield_session_token,
        db=db,
        required_roles=None,
    )


def require_admin_role(
    request: Request,
    x_session_id: str | None = Header(default=None, alias="X-Session-Id"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    x_session_token: str | None = Header(default=None, alias="X-Session-Token"),
    qshield_session_id: str | None = Cookie(default=None),
    qshield_session_token: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> tuple[AuthSession, Actor]:
    return _get_auth_context(
        request,
        x_session_id=x_session_id,
        authorization=authorization,
        x_session_token=x_session_token,
        qshield_session_id=qshield_session_id,
        qshield_session_token=qshield_session_token,
        db=db,
        required_roles={"Admin"},
    )


class UserRegisterReq(BaseModel):
    actor_id: str = Field(min_length=2, max_length=64)
    display_label: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=128)
    password: str = Field(min_length=8, max_length=128)
    confirm_password: str | None = Field(default=None, min_length=8, max_length=128)


class RoleLoginReq(BaseModel):
    identifier: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=128)
    expected_role: Literal["User", "Employee", "Admin"]
    device_id: str | None = Field(default=None, min_length=1, max_length=64)
    peer_id: str = Field(default="web-console", min_length=1, max_length=64)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)


class CameraCheckpointReq(BaseModel):
    consent_granted: bool
    action: Literal["COMPLETED", "CANCELLED", "DENIED"]


class AdminCreateUserReq(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    display_label: str = Field(min_length=1, max_length=128)
    email: str = Field(min_length=3, max_length=128)
    role: Literal["User", "Employee", "Admin"]
    password: str = Field(min_length=8, max_length=128)
    device_id: str = Field(min_length=1, max_length=64)


class AdminUpdateRoleReq(BaseModel):
    role: Literal["User", "Employee", "Admin"]


class AdminUpdateStatusReq(BaseModel):
    enabled: bool


class CreateProtectedFileReq(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    classification: str = Field(default="CONFIDENTIAL", min_length=1, max_length=32)
    required_role: Literal["User", "Employee", "Admin"]
    assigned_actor_id: str | None = Field(default=None, max_length=64)
    content_text: str = Field(min_length=1, max_length=65536)


@rbac_auth_router.post("/auth/register", status_code=status.HTTP_201_CREATED, tags=["rbac-auth"])
def register_user_endpoint(
    payload: UserRegisterReq,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Public registration endpoint: creates User accounts only (never Employee or Admin) and starts an authenticated session."""
    if payload.confirm_password is not None and payload.password != payload.confirm_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Passwords do not match")
    try:
        actor = provision_rbac_account(
            db,
            actor_id=payload.actor_id.strip(),
            display_label=payload.display_label.strip(),
            email=payload.email.strip().lower(),
            role="User",
            password=payload.password,
            device_id=f"dev-{payload.actor_id.strip()}",
            operator_actor_id="self-registration",
            correlation_id=_cid(request),
        )
    except DomainValidationError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    session, raw_token, actor = role_login(
        db,
        identifier=actor.id,
        password=payload.password,
        expected_role="User",
        device_id=f"dev-{actor.id}",
        peer_id="web-console",
        ttl_seconds=None,
        correlation_id=_cid(request),
    )
    is_secure = get_settings().environment != "local"
    response.set_cookie(key="qshield_session_id", value=session.id, httponly=True, samesite="lax", secure=is_secure)
    response.set_cookie(key="qshield_session_token", value=raw_token, httponly=True, samesite="lax", secure=is_secure)
    return {
        "actor_id": actor.id,
        "display_label": actor.display_label,
        "email": actor.email,
        "role": actor.role,
        "status": "REGISTERED",
        "session_id": session.id,
        "session_token": raw_token,
        "device_id": session.device_id,
        "peer_id": session.peer_id,
        "issued_at": session.issued_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "session_secret_bound": session.session_secret_hash is not None,
    }


class PasskeyLoginOptionsReq(BaseModel):
    identifier: str = Field(min_length=1, max_length=128)
    rp_id: str = Field(default="localhost", min_length=1, max_length=128)


class PasskeyLoginVerifyReq(BaseModel):
    identifier: str = Field(min_length=1, max_length=128)
    challenge_id: str = Field(min_length=1, max_length=64)
    credential: dict[str, object]
    rp_id: str = Field(default="localhost", min_length=1, max_length=128)
    origin: str = Field(default="http://localhost:5173", min_length=1, max_length=256)


@rbac_auth_router.post("/auth/passkey-login/options", tags=["rbac-auth"])
def passkey_login_options_endpoint(
    payload: PasskeyLoginOptionsReq,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    ident = payload.identifier.strip()
    actor = db.execute(
        select(Actor).where(or_(Actor.id == ident, Actor.email == ident.lower()))
    ).scalar_one_or_none()
    if actor is None or not actor.enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found or disabled")
    try:
        return generate_authenticate_options(db, actor_id=actor.id, rp_id=payload.rp_id)
    except DomainValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@rbac_auth_router.post("/auth/passkey-login/verify", tags=["rbac-auth"])
def passkey_login_verify_endpoint(
    payload: PasskeyLoginVerifyReq,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    ident = payload.identifier.strip()
    actor = db.execute(
        select(Actor).where(or_(Actor.id == ident, Actor.email == ident.lower()))
    ).scalar_one_or_none()
    if actor is None or not actor.enabled:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found or disabled")

    cid = _cid(request)
    try:
        verify_authentication(
            db,
            actor_id=actor.id,
            challenge_id=payload.challenge_id,
            credential_json=payload.credential,
            rp_id=payload.rp_id,
            origin=payload.origin,
            correlation_id=cid,
        )
    except DomainValidationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    dev = db.execute(
        select(Device).where(Device.owner_actor_id == actor.id, Device.state == "TRUSTED")
    ).scalars().first()
    if dev is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No trusted device bound to account")

    session, raw_token = create_session(
        db,
        actor_id=actor.id,
        device_id=dev.id,
        peer_id="web-console",
        ttl_seconds=None,
        correlation_id=cid,
    )
    raw_secret = secrets.token_bytes(32)
    session.session_secret_hash = hashlib.sha256(raw_secret).hexdigest()
    session.identity_verified_at = datetime.now(timezone.utc)
    session.verification_method = "WEBAUTHN"
    db.commit()
    db.refresh(session)

    is_secure = get_settings().environment != "local"
    response.set_cookie(key="qshield_session_id", value=session.id, httponly=True, samesite="lax", secure=is_secure)
    response.set_cookie(key="qshield_session_token", value=raw_token, httponly=True, samesite="lax", secure=is_secure)

    record_audit_event(
        db,
        actor_id=actor.id,
        action="auth:login:passkey",
        target=session.id,
        decision="ALLOW",
        reason=f"Authenticated {actor.role} session via WebAuthn passkey",
        correlation_id=cid,
        metadata={"role": actor.role, "entropy_bits": 256},
    )
    return {
        "session_id": session.id,
        "session_token": raw_token,
        "actor_id": actor.id,
        "display_label": actor.display_label,
        "email": actor.email,
        "role": actor.role,
        "device_id": session.device_id,
        "peer_id": session.peer_id,
        "issued_at": session.issued_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "session_secret_bound": True,
        "identity_verified": True,
        "verification_method": "WEBAUTHN",
    }


@rbac_auth_router.post("/auth/role-login", tags=["rbac-auth"])
def role_login_endpoint(
    payload: RoleLoginReq,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict[str, object]:
    try:
        session, raw_token, actor = role_login(
            db,
            identifier=payload.identifier,
            password=payload.password,
            expected_role=payload.expected_role,
            device_id=payload.device_id,
            peer_id=payload.peer_id,
            ttl_seconds=payload.ttl_seconds,
            correlation_id=_cid(request),
        )
    except PermissionError as exc:
        code = status.HTTP_429_TOO_MANY_REQUESTS if "locked" in str(exc).lower() else status.HTTP_403_FORBIDDEN
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    except DomainValidationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    is_secure = get_settings().environment != "local"
    response.set_cookie(
        key="qshield_session_id",
        value=session.id,
        httponly=True,
        samesite="lax",
        secure=is_secure,
    )
    response.set_cookie(
        key="qshield_session_token",
        value=raw_token,
        httponly=True,
        samesite="lax",
        secure=is_secure,
    )

    return {
        "session_id": session.id,
        "session_token": raw_token,
        "actor_id": actor.id,
        "display_label": actor.display_label,
        "email": actor.email,
        "role": actor.role,
        "device_id": session.device_id,
        "peer_id": session.peer_id,
        "issued_at": session.issued_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
        "session_secret_bound": session.session_secret_hash is not None,
        "identity_verified": session.identity_verified_at is not None,
        "verification_method": session.verification_method,
    }


@rbac_auth_router.get("/auth/session-status", tags=["rbac-auth"])
def session_status_endpoint(
    ctx: tuple[AuthSession, Actor] = Depends(require_any_role),
) -> dict[str, object]:
    sess, actor = ctx
    now = datetime.now(timezone.utc)
    exp = sess.expires_at if sess.expires_at.tzinfo is not None else sess.expires_at.replace(tzinfo=timezone.utc)
    seconds_remaining = max(0, int((exp - now).total_seconds()))
    return {
        "valid": True,
        "session_id": sess.id,
        "actor_id": actor.id,
        "display_label": actor.display_label,
        "email": actor.email,
        "role": actor.role,
        "device_id": sess.device_id,
        "issued_at": sess.issued_at.isoformat(),
        "expires_at": sess.expires_at.isoformat(),
        "seconds_remaining": seconds_remaining,
        "identity_verified": sess.identity_verified_at is not None,
        "verification_method": sess.verification_method,
        "session_secret_bound": sess.session_secret_hash is not None,
    }


@rbac_auth_router.post("/auth/logout", tags=["rbac-auth"])
def logout_endpoint(
    request: Request,
    response: Response,
    ctx: tuple[AuthSession, Actor] = Depends(require_any_role),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    sess, _ = ctx
    logout_session(db, session=sess, correlation_id=_cid(request))
    response.delete_cookie("qshield_session_id")
    response.delete_cookie("qshield_session_token")
    return {"status": "LOGGED_OUT", "session_id": sess.id}


@rbac_auth_router.post("/auth/camera-checkpoint", tags=["rbac-auth"])
def camera_checkpoint_endpoint(
    payload: CameraCheckpointReq,
    request: Request,
    ctx: tuple[AuthSession, Actor] = Depends(require_any_role),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    """Record explicit camera consent/presence audit event only (never claims facial recognition)."""
    sess, actor = ctx
    cid = _cid(request)
    record_audit_event(
        db,
        actor_id=actor.id,
        action="auth:camera:checkpoint",
        target=sess.id,
        decision="ALLOW" if payload.consent_granted and payload.action == "COMPLETED" else "DENY",
        reason=f"Camera visual preview {payload.action.lower()} (non-biometric; facial recognition NOT IMPLEMENTED)",
        correlation_id=cid,
    )
    return {
        "camera_preview_completed": payload.consent_granted and payload.action == "COMPLETED",
        "face_recognition": "NOT_IMPLEMENTED",
        "actor_id": actor.id,
    }


@rbac_auth_router.get("/files", tags=["files"])
def list_files_endpoint(
    ctx: tuple[AuthSession, Actor] = Depends(require_any_role),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    _, actor = ctx
    rows = list_accessible_files(db, actor=actor)
    return [
        {
            "id": f.id,
            "name": f.name,
            "classification": f.classification,
            "required_role": f.required_role,
            "assigned_actor_id": f.assigned_actor_id,
            "created_at": f.created_at.isoformat(),
        }
        for f in rows
    ]


@rbac_auth_router.get("/files/{file_id}/download", tags=["files"])
def download_file_endpoint(
    file_id: str,
    request: Request,
    ctx: tuple[AuthSession, Actor] = Depends(require_any_role),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    _, actor = ctx
    try:
        row = read_protected_file(db, actor=actor, file_id=file_id, correlation_id=_cid(request))
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return {
        "id": row.id,
        "name": row.name,
        "classification": row.classification,
        "required_role": row.required_role,
        "assigned_actor_id": row.assigned_actor_id,
        "content_text": row.content_text,
    }


@rbac_auth_router.post("/files", status_code=status.HTTP_201_CREATED, tags=["files"])
def create_file_endpoint(
    payload: CreateProtectedFileReq,
    request: Request,
    ctx: tuple[AuthSession, Actor] = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    _, admin_actor = ctx
    row = create_protected_file(
        db,
        name=payload.name,
        classification=payload.classification,
        required_role=payload.required_role,
        assigned_actor_id=payload.assigned_actor_id,
        content_text=payload.content_text,
        operator_actor_id=admin_actor.id,
        correlation_id=_cid(request),
    )
    return {"id": row.id, "name": row.name, "required_role": row.required_role}


@rbac_auth_router.get("/admin/users", tags=["admin"])
def admin_list_users_endpoint(
    _ctx: tuple[AuthSession, Actor] = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    actors = db.execute(select(Actor).order_by(Actor.created_at.asc())).scalars().all()
    return [
        {
            "id": a.id,
            "display_label": a.display_label,
            "email": a.email,
            "role": a.role,
            "enabled": a.enabled,
            "locked": a.locked_until is not None and a.locked_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc),
            "created_at": a.created_at.isoformat(),
        }
        for a in actors
    ]


@rbac_auth_router.post("/admin/users", status_code=status.HTTP_201_CREATED, tags=["admin"])
def admin_create_user_endpoint(
    payload: AdminCreateUserReq,
    request: Request,
    ctx: tuple[AuthSession, Actor] = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    _, admin_actor = ctx
    actor = provision_rbac_account(
        db,
        actor_id=payload.actor_id,
        display_label=payload.display_label,
        email=payload.email,
        role=payload.role,
        password=payload.password,
        device_id=payload.device_id,
        operator_actor_id=admin_actor.id,
        correlation_id=_cid(request),
    )
    return {"id": actor.id, "role": actor.role, "email": actor.email, "enabled": actor.enabled}


@rbac_auth_router.post("/admin/users/{actor_id}/role", tags=["admin"])
def admin_update_role_endpoint(
    actor_id: str,
    payload: AdminUpdateRoleReq,
    request: Request,
    ctx: tuple[AuthSession, Actor] = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    _, admin_actor = ctx
    target = db.get(Actor, actor_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")
    old_role = target.role
    target.role = payload.role
    now = datetime.now(timezone.utc)
    for s in db.execute(select(AuthSession).where(AuthSession.actor_id == actor_id, AuthSession.revoked_at.is_(None))).scalars():
        s.revoked_at = now
        s.session_secret_hash = None
    db.commit()
    record_audit_event(
        db,
        actor_id=admin_actor.id,
        action="admin:role:update",
        target=actor_id,
        decision="ALLOW",
        reason=f"Role changed from {old_role} to {payload.role}",
        correlation_id=_cid(request),
    )
    return {"id": target.id, "role": target.role}


@rbac_auth_router.post("/admin/users/{actor_id}/status", tags=["admin"])
def admin_update_status_endpoint(
    actor_id: str,
    payload: AdminUpdateStatusReq,
    request: Request,
    ctx: tuple[AuthSession, Actor] = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    _, admin_actor = ctx
    target = db.get(Actor, actor_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Actor not found")
    target.enabled = payload.enabled
    if not payload.enabled:
        now = datetime.now(timezone.utc)
        for s in db.execute(select(AuthSession).where(AuthSession.actor_id == actor_id, AuthSession.revoked_at.is_(None))).scalars():
            s.revoked_at = now
            s.session_secret_hash = None
    db.commit()
    record_audit_event(
        db,
        actor_id=admin_actor.id,
        action="admin:account:status",
        target=actor_id,
        decision="ALLOW",
        reason=f"Account enabled={payload.enabled}",
        correlation_id=_cid(request),
    )
    return {"id": target.id, "enabled": target.enabled}


@rbac_auth_router.get("/admin/audit", tags=["admin"])
def admin_audit_endpoint(
    _ctx: tuple[AuthSession, Actor] = Depends(require_admin_role),
    db: Session = Depends(get_db),
) -> list[dict[str, object]]:
    events = db.execute(select(AuditEvent).order_by(AuditEvent.seq.desc()).limit(50)).scalars().all()
    return [
        {
            "seq": e.seq,
            "actor_id": e.actor_id,
            "action": e.action,
            "target": e.target,
            "decision": e.decision,
            "reason": e.reason,
            "timestamp": e.timestamp.isoformat(),
        }
        for e in events
    ]

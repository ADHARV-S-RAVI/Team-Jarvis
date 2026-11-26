"""Advanced RBAC authentication, 256-bit session secrets, session monitoring, and protected file access."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
import threading
import uuid

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from backend.app.db.models import Actor, AuthSession, Device, ProtectedFile
from backend.app.services.foundation_service import (
    DomainNotFoundError,
    DomainValidationError,
    create_session,
    hash_password,
    record_audit_event,
    verify_password,
)

RBAC_ROLES = {"User", "Employee", "Admin"}

_ROLE_LOCK = threading.Lock()
_ROLE_FAIL_WINDOWS: dict[str, list[datetime]] = {}
_MAX_FAILS = 5
_WINDOW_SECONDS = 60
_LOCKOUT_SECONDS = 60


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def provision_rbac_account(
    db: Session,
    *,
    actor_id: str,
    display_label: str,
    email: str,
    role: str,
    password: str,
    device_id: str,
    operator_actor_id: str,
    correlation_id: str,
) -> Actor:
    """Create a User, Employee, or Admin account with a salted scrypt password and trusted device."""
    if role not in RBAC_ROLES:
        raise DomainValidationError(f"Unsupported RBAC role '{role}'")
    existing = db.get(Actor, actor_id)
    if existing is not None:
        raise DomainValidationError(f"Actor '{actor_id}' already exists")
    email_norm = email.strip().lower()
    existing_email = db.execute(select(Actor).where(Actor.email == email_norm)).scalar_one_or_none()
    if existing_email is not None:
        raise DomainValidationError(f"Email '{email_norm}' is already registered")

    actor = Actor(
        id=actor_id,
        display_label=display_label,
        email=email.strip().lower(),
        role=role,
        enabled=True,
        password_hash=hash_password(password),
    )
    db.add(actor)
    db.flush()

    if db.get(Device, device_id) is None:
        db.add(
            Device(
                id=device_id,
                owner_actor_id=actor_id,
                credential_fingerprint=f"fp-{actor_id}-rbac",
                state="TRUSTED",
            )
        )
    db.commit()
    db.refresh(actor)
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="admin:account:provision",
        target=actor_id,
        decision="ALLOW",
        reason=f"Provisioned {role} account",
        correlation_id=correlation_id,
        metadata={"role": role, "email": actor.email},
    )
    return actor


def role_login(
    db: Session,
    *,
    identifier: str,
    password: str,
    expected_role: str,
    device_id: str | None,
    peer_id: str,
    ttl_seconds: int | None,
    correlation_id: str,
) -> tuple[AuthSession, str, Actor]:
    """Authenticate by username/email + password, verify actual DB role, and bind a 256-bit session secret."""
    ident_norm = identifier.strip()
    actor = db.execute(
        select(Actor).where(or_(Actor.id == ident_norm, Actor.email == ident_norm.lower()))
    ).scalar_one_or_none()

    now = _utcnow()
    key = actor.id if actor is not None else ident_norm

    if actor is not None and actor.locked_until is not None and _as_utc(actor.locked_until) > now:
        record_audit_event(
            db,
            actor_id=actor.id,
            action="auth:login:locked",
            target=actor.id,
            decision="DENY",
            reason="Account temporarily locked after repeated failed attempts",
            correlation_id=correlation_id,
        )
        raise PermissionError("Account temporarily locked due to repeated failed attempts")

    if actor is None or not actor.enabled or not verify_password(password, actor.password_hash):
        with _ROLE_LOCK:
            cutoff = now - timedelta(seconds=_WINDOW_SECONDS)
            recent = [ts for ts in _ROLE_FAIL_WINDOWS.get(key, []) if ts >= cutoff]
            recent.append(now)
            _ROLE_FAIL_WINDOWS[key] = recent
            if len(recent) >= _MAX_FAILS and actor is not None:
                actor.locked_until = now + timedelta(seconds=_LOCKOUT_SECONDS)
                db.commit()
        record_audit_event(
            db,
            actor_id=key,
            action="auth:login:failed",
            target=key,
            decision="DENY",
            reason="Invalid username/email, password, or disabled account",
            correlation_id=correlation_id,
        )
        raise DomainValidationError("Invalid credentials")

    if actor.role != expected_role:
        record_audit_event(
            db,
            actor_id=actor.id,
            action="auth:role:spoof_attempt",
            target=actor.id,
            decision="DENY",
            reason=f"Role mismatch: claimed '{expected_role}', actual '{actor.role}'",
            correlation_id=correlation_id,
            metadata={"claimed_role": expected_role, "actual_role": actor.role},
        )
        raise PermissionError(f"Assigned role verification failed for account '{actor.id}'")

    # Clear failure counter & lockout on verified credentials + role
    with _ROLE_LOCK:
        _ROLE_FAIL_WINDOWS.pop(actor.id, None)
    if actor.locked_until is not None:
        actor.locked_until = None
        db.commit()

    resolved_device_id = device_id
    if not resolved_device_id:
        dev = db.execute(
            select(Device).where(Device.owner_actor_id == actor.id, Device.state == "TRUSTED")
        ).scalars().first()
        if dev is None:
            raise DomainValidationError("No trusted device bound to account")
        resolved_device_id = dev.id

    session, raw_token = create_session(
        db,
        actor_id=actor.id,
        device_id=resolved_device_id,
        peer_id=peer_id,
        ttl_seconds=ttl_seconds,
        correlation_id=correlation_id,
    )

    # Generate 256-bit cryptographically secure session secret; store SHA-256 hash only.
    raw_secret = secrets.token_bytes(32)
    session.session_secret_hash = hashlib.sha256(raw_secret).hexdigest()
    session.verification_method = "PASSWORD"
    db.commit()
    db.refresh(session)

    record_audit_event(
        db,
        actor_id=actor.id,
        action="session:secret:create",
        target=session.id,
        decision="ALLOW",
        reason="Generated 256-bit session secret hash",
        correlation_id=correlation_id,
        metadata={"entropy_bits": 256},
    )
    record_audit_event(
        db,
        actor_id=actor.id,
        action="auth:login:success",
        target=session.id,
        decision="ALLOW",
        reason=f"Authenticated {actor.role} session",
        correlation_id=correlation_id,
        metadata={"role": actor.role, "device_id": resolved_device_id},
    )
    return session, raw_token, actor


def authenticate_session_request(
    db: Session,
    *,
    session_id: str | None,
    session_token: str | None,
    required_roles: set[str] | None = None,
    correlation_id: str = "req",
) -> tuple[AuthSession, Actor]:
    """Verify session ID, token hash, expiry, revocation, actor enabled state, and RBAC role."""
    if not session_id or not session_token:
        raise DomainValidationError("Missing session credentials")

    sess = db.get(AuthSession, session_id)
    if sess is None:
        raise DomainValidationError("Invalid session")

    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    if not hmac.compare_digest(sess.token_hash, token_hash):
        raise DomainValidationError("Invalid session token")

    if sess.revoked_at is not None:
        raise DomainValidationError("Session revoked")

    now = _utcnow()
    if _as_utc(sess.expires_at) <= now:
        record_audit_event(
            db,
            actor_id=sess.actor_id,
            action="auth:session:expired",
            target=sess.id,
            decision="DENY",
            reason="Session expired",
            correlation_id=correlation_id,
        )
        raise DomainValidationError("Session expired")

    actor = db.get(Actor, sess.actor_id)
    if actor is None or not actor.enabled:
        raise DomainValidationError("Actor disabled or missing")

    device = db.get(Device, sess.device_id)
    if device is None or device.state != "TRUSTED":
        raise DomainValidationError("Bound device is not trusted")

    if required_roles is not None and actor.role not in required_roles:
        record_audit_event(
            db,
            actor_id=actor.id,
            action="auth:rbac:deny",
            target=",".join(sorted(required_roles)),
            decision="DENY",
            reason=f"Role '{actor.role}' lacks required role(s)",
            correlation_id=correlation_id,
        )
        raise PermissionError("Insufficient role permissions")

    return sess, actor


def logout_session(
    db: Session,
    *,
    session: AuthSession,
    correlation_id: str,
) -> None:
    """Invalidate session and its 256-bit session secret hash on logout."""
    now = _utcnow()
    session.revoked_at = now
    session.session_secret_hash = None
    db.commit()
    record_audit_event(
        db,
        actor_id=session.actor_id,
        action="session:secret:invalidated",
        target=session.id,
        decision="REVOKED",
        reason="Session secret invalidated on logout",
        correlation_id=correlation_id,
    )
    record_audit_event(
        db,
        actor_id=session.actor_id,
        action="auth:logout",
        target=session.id,
        decision="REVOKED",
        reason="User logged out",
        correlation_id=correlation_id,
    )


def mark_session_verified(
    db: Session,
    *,
    session: AuthSession,
    method: str,
    correlation_id: str,
) -> AuthSession:
    """Record explicit verification checkpoint completion on the session."""
    session.identity_verified_at = _utcnow()
    session.verification_method = method
    db.commit()
    db.refresh(session)
    record_audit_event(
        db,
        actor_id=session.actor_id,
        action="auth:identity:checkpoint",
        target=session.id,
        decision="ALLOW",
        reason=f"Identity verification checkpoint recorded ({method})",
        correlation_id=correlation_id,
        metadata={"method": method},
    )
    return session


def can_access_file(actor: Actor, file_row: ProtectedFile) -> bool:
    """Backend RBAC + ownership check for ProtectedFile."""
    if actor.role == "Admin":
        return True
    if actor.role == "Employee":
        if file_row.required_role not in {"User", "Employee"}:
            return False
        return file_row.assigned_actor_id in {None, actor.id}
    if actor.role in {"User", "Owner/User"}:
        if file_row.required_role != "User":
            return False
        return file_row.assigned_actor_id in {None, actor.id}
    return False


def list_accessible_files(db: Session, *, actor: Actor) -> list[ProtectedFile]:
    rows = db.execute(select(ProtectedFile).order_by(ProtectedFile.created_at.desc())).scalars().all()
    return [r for r in rows if can_access_file(actor, r)]


def read_protected_file(
    db: Session,
    *,
    actor: Actor,
    file_id: str,
    correlation_id: str,
) -> ProtectedFile:
    file_row = db.get(ProtectedFile, file_id)
    if file_row is None:
        raise DomainNotFoundError(f"File '{file_id}' not found")
    if not can_access_file(actor, file_row):
        record_audit_event(
            db,
            actor_id=actor.id,
            action="file:access:denied",
            target=file_id,
            decision="DENY",
            reason=f"Role '{actor.role}' cannot access '{file_row.required_role}' file",
            correlation_id=correlation_id,
        )
        raise PermissionError("Access denied to protected file")
    record_audit_event(
        db,
        actor_id=actor.id,
        action="file:access:allow",
        target=file_id,
        decision="ALLOW",
        reason="Authorized protected file download",
        correlation_id=correlation_id,
        metadata={"classification": file_row.classification},
    )
    return file_row


def create_protected_file(
    db: Session,
    *,
    name: str,
    classification: str,
    required_role: str,
    assigned_actor_id: str | None,
    content_text: str,
    operator_actor_id: str,
    correlation_id: str,
) -> ProtectedFile:
    if required_role not in RBAC_ROLES:
        raise DomainValidationError(f"Invalid required_role '{required_role}'")
    row = ProtectedFile(
        id=f"file-{uuid.uuid4().hex[:10]}",
        name=name,
        classification=classification,
        required_role=required_role,
        assigned_actor_id=assigned_actor_id,
        content_text=content_text,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="file:create",
        target=row.id,
        decision="ALLOW",
        reason=f"Created protected file '{name}' for role '{required_role}'",
        correlation_id=correlation_id,
    )
    return row

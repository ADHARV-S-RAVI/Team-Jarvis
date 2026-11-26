"""Foundational domain services for Stage 2 (identities, devices, sessions, resources, revocations, audit)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import threading
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

_AUDIT_LOCK = threading.RLock()
_LOGIN_FAIL_LOCK = threading.Lock()
_LOGIN_FAIL_WINDOWS: dict[str, list[datetime]] = {}
_LOGIN_MAX_FAILURES = 5
_LOGIN_WINDOW_SECONDS = 60

from backend.app.audit.service import append_audit_event
from backend.app.config import get_settings
from backend.app.db.models import (
    Actor,
    AuditEvent,
    AuthSession,
    Device,
    KeyMetadata,
    Resource,
    RevocationTombstone,
    RolePermission,
)

DEFAULT_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "Owner/User": ["resource:read", "device:enroll"],
    "Security Operator": ["resource:read", "device:revoke", "actor:revoke", "incident:manage"],
    "Admin": ["resource:read", "policy:configure", "actor:manage"],
    "Auditor": ["audit:read"],
}


class DomainConflictError(Exception):
    """Raised when creating an entity that already exists."""


class DomainNotFoundError(Exception):
    """Raised when a referenced entity does not exist."""


class DomainValidationError(Exception):
    """Raised when a domain invariant is violated."""


def ensure_foundation_defaults(db: Session) -> None:
    """Seed idempotent RBAC role permissions and initial active key metadata v1 if absent."""
    existing_perms = {
        (rp.role, rp.permission)
        for rp in db.execute(select(RolePermission)).scalars().all()
    }
    for role, perms in DEFAULT_ROLE_PERMISSIONS.items():
        for perm in perms:
            if (role, perm) not in existing_perms:
                db.add(RolePermission(role=role, permission=perm))

    key_v1 = db.execute(select(KeyMetadata).where(KeyMetadata.version == 1)).scalar_one_or_none()
    if key_v1 is None:
        now = datetime.now(timezone.utc)
        db.add(
            KeyMetadata(
                id="key-v1-default",
                version=1,
                algorithm="AES-256-GCM",
                state="ACTIVE",
                created_at=now,
                activated_at=now,
            )
        )
    db.commit()


def record_audit_event(
    db: Session,
    *,
    actor_id: str,
    action: str,
    target: str,
    decision: str,
    reason: str,
    correlation_id: str,
    metadata: dict[str, str | int | bool | None] | None = None,
) -> AuditEvent:
    """Append a sanitized, hash-chained audit event via backend.app.audit.service."""
    return append_audit_event(
        db,
        actor_id=actor_id,
        action=action,
        target=target,
        decision=decision,
        reason=reason,
        correlation_id=correlation_id,
        metadata=metadata,  # type: ignore[arg-type]
    )


def create_identity(
    db: Session,
    *,
    actor_id: str,
    display_label: str,
    role: str,
    enabled: bool,
    correlation_id: str,
) -> Actor:
    ensure_foundation_defaults(db)
    if db.get(Actor, actor_id) is not None:
        raise DomainConflictError(f"Identity '{actor_id}' already exists")
    actor = Actor(id=actor_id, display_label=display_label, role=role, enabled=enabled)
    db.add(actor)
    db.commit()
    db.refresh(actor)
    record_audit_event(
        db,
        actor_id="system",
        action="identity:create",
        target=actor.id,
        decision="ALLOW",
        reason="CREATED",
        correlation_id=correlation_id,
        metadata={"role": role, "enabled": enabled},
    )
    return actor


def get_identity(db: Session, actor_id: str) -> Actor:
    actor = db.get(Actor, actor_id)
    if actor is None:
        raise DomainNotFoundError(f"Identity '{actor_id}' not found")
    return actor


def create_device(
    db: Session,
    *,
    device_id: str,
    owner_actor_id: str,
    credential_fingerprint: str,
    state: str,
    correlation_id: str,
) -> Device:
    actor = db.get(Actor, owner_actor_id)
    if actor is None:
        raise DomainNotFoundError(f"Owner identity '{owner_actor_id}' not found")
    if db.get(Device, device_id) is not None:
        raise DomainConflictError(f"Device '{device_id}' already exists")
    device = Device(
        id=device_id,
        owner_actor_id=owner_actor_id,
        credential_fingerprint=credential_fingerprint,
        state=state,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    record_audit_event(
        db,
        actor_id=owner_actor_id,
        action="device:register",
        target=device.id,
        decision="ALLOW",
        reason="REGISTERED",
        correlation_id=correlation_id,
        metadata={"state": state},
    )
    return device


def get_device(db: Session, device_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise DomainNotFoundError(f"Device '{device_id}' not found")
    return device


def create_session(
    db: Session,
    *,
    actor_id: str,
    device_id: str,
    peer_id: str,
    ttl_seconds: int | None,
    correlation_id: str,
) -> tuple[AuthSession, str]:
    actor = db.get(Actor, actor_id)
    if actor is None or not actor.enabled:
        raise DomainValidationError("Identity does not exist or is disabled")
    device = db.get(Device, device_id)
    if device is None or device.owner_actor_id != actor_id or device.state != "TRUSTED":
        raise DomainValidationError("Device does not belong to actor or is not trusted")

    ttl = ttl_seconds or get_settings().session_ttl_seconds
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now = datetime.now(timezone.utc)
    session = AuthSession(
        id=str(uuid.uuid4()),
        token_hash=token_hash,
        actor_id=actor_id,
        device_id=device_id,
        peer_id=peer_id,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    record_audit_event(
        db,
        actor_id=actor_id,
        action="session:create",
        target=session.id,
        decision="ALLOW",
        reason="SESSION_ISSUED",
        correlation_id=correlation_id,
        metadata={"device_id": device_id, "peer_id": peer_id},
    )
    return session, raw_token


def validate_session(
    db: Session,
    *,
    session_id: str,
    session_token: str,
    actor_id: str,
    device_id: str,
    peer_id: str | None,
) -> AuthSession:
    session = db.get(AuthSession, session_id)
    if session is None:
        raise DomainNotFoundError("Session not found")
    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    if (
        session.token_hash != token_hash
        or session.actor_id != actor_id
        or session.device_id != device_id
        or (peer_id is not None and session.peer_id != peer_id)
        or session.revoked_at is not None
    ):
        raise DomainValidationError("Session binding or revocation check failed")
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        raise DomainValidationError("Session expired")
    return session


def revoke_session(
    db: Session,
    *,
    session_id: str,
    actor_id: str,
    reason: str = "User logout / session invalidation",
    correlation_id: str = "session-revoke",
) -> AuthSession:
    """Immediately invalidate a session and commit a session revocation tombstone."""
    session = db.get(AuthSession, session_id)
    if session is None:
        raise DomainNotFoundError("Session not found")
    if session.actor_id != actor_id:
        raise DomainValidationError("Session does not belong to actor")

    now = datetime.now(timezone.utc)
    if session.revoked_at is None:
        session.revoked_at = now
        session.version += 1

    tombstone = RevocationTombstone(
        subject_type="session",
        subject_id=session_id,
        epoch=1,
        reason=reason,
    )
    db.add(tombstone)
    db.commit()
    db.refresh(session)
    record_audit_event(
        db,
        actor_id=actor_id,
        action="session:revoke",
        target=session.id,
        decision="REVOKED",
        reason=reason,
        correlation_id=correlation_id,
    )
    return session


def create_resource(
    db: Session,
    *,
    resource_id: str,
    owner_actor_id: str,
    content_ref: str,
    key_version: int,
    state: str,
    correlation_id: str,
) -> Resource:
    ensure_foundation_defaults(db)
    if db.get(Actor, owner_actor_id) is None:
        raise DomainNotFoundError(f"Owner identity '{owner_actor_id}' not found")
    if db.get(Resource, resource_id) is not None:
        raise DomainConflictError(f"Resource '{resource_id}' already exists")
    resource = Resource(
        id=resource_id,
        owner_actor_id=owner_actor_id,
        content_ref=content_ref,
        key_version=key_version,
        state=state,
    )
    db.add(resource)
    db.commit()
    db.refresh(resource)
    record_audit_event(
        db,
        actor_id=owner_actor_id,
        action="resource:register",
        target=resource.id,
        decision="ALLOW",
        reason="REGISTERED",
        correlation_id=correlation_id,
        metadata={"key_version": key_version, "state": state},
    )
    return resource


def get_resource(db: Session, resource_id: str) -> Resource:
    resource = db.get(Resource, resource_id)
    if resource is None:
        raise DomainNotFoundError(f"Resource '{resource_id}' not found")
    return resource


def create_revocation(
    db: Session,
    *,
    subject_type: str,
    subject_id: str,
    reason: str,
    correlation_id: str,
) -> RevocationTombstone:
    max_epoch = (
        db.execute(
            select(func.max(RevocationTombstone.epoch)).where(
                RevocationTombstone.subject_type == subject_type,
                RevocationTombstone.subject_id == subject_id,
            )
        ).scalar_one_or_none()
        or 0
    )
    tombstone = RevocationTombstone(
        subject_type=subject_type,
        subject_id=subject_id,
        epoch=max_epoch + 1,
        reason=reason,
    )
    db.add(tombstone)

    # Synchronize target state durably in the same transaction
    now = datetime.now(timezone.utc)
    if subject_type == "actor":
        actor = db.get(Actor, subject_id)
        if actor is not None:
            actor.enabled = False
    elif subject_type == "device":
        device = db.get(Device, subject_id)
        if device is not None:
            device.state = "REVOKED"
            device.state_version += 1
            device.revocation_reason = reason
    elif subject_type == "session":
        session = db.get(AuthSession, subject_id)
        if session is not None and session.revoked_at is None:
            session.revoked_at = now
    elif subject_type == "key":
        key_meta = db.get(KeyMetadata, subject_id)
        if key_meta is not None:
            key_meta.state = "REVOKED"
            key_meta.retired_at = now

    db.commit()
    db.refresh(tombstone)
    record_audit_event(
        db,
        actor_id="system",
        action="revocation:create",
        target=f"{subject_type}:{subject_id}",
        decision="REVOKED",
        reason=reason,
        correlation_id=correlation_id,
        metadata={"epoch": tombstone.epoch},
    )
    return tombstone


def get_revocation_status(
    db: Session, *, subject_type: str, subject_id: str
) -> tuple[bool, int, int | None, str | None]:
    tombstones = (
        db.execute(
            select(RevocationTombstone)
            .where(
                RevocationTombstone.subject_type == subject_type,
                RevocationTombstone.subject_id == subject_id,
            )
            .order_by(RevocationTombstone.epoch.desc())
        )
        .scalars()
        .all()
    )
    if not tombstones:
        return False, 0, None, None
    latest = tombstones[0]
    return True, len(tombstones), latest.epoch, latest.reason


def hash_password(password: str) -> str:
    """Hash a password with scrypt and a random 16-byte salt."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str | None) -> bool:
    """Verify a password against a stored scrypt hash in constant time."""
    if not stored_hash:
        return False
    parts = stored_hash.split("$")
    if len(parts) != 6 or parts[0] != "scrypt":
        return False
    try:
        n, r, p = int(parts[1]), int(parts[2]), int(parts[3])
        salt = bytes.fromhex(parts[4])
        expected_dk = bytes.fromhex(parts[5])
    except ValueError:
        return False
    actual_dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=len(expected_dk))
    return hmac.compare_digest(actual_dk, expected_dk)


def set_actor_password(
    db: Session,
    *,
    actor_id: str,
    password: str,
    correlation_id: str,
    current_password: str | None = None,
    operator_actor_id: str | None = None,
    session_id: str | None = None,
    session_token: str | None = None,
) -> Actor:
    """Set or rotate a salted scrypt password hash with authorization and session revocation."""
    actor = db.get(Actor, actor_id)
    if actor is None:
        raise DomainNotFoundError(f"Identity '{actor_id}' not found")

    authorized = False
    if operator_actor_id and session_id and session_token:
        op_actor = db.get(Actor, operator_actor_id)
        if op_actor is not None and op_actor.enabled and op_actor.role == "Admin":
            try:
                validate_session(
                    db,
                    session_id=session_id,
                    session_token=session_token,
                    actor_id=operator_actor_id,
                    device_id=None,
                )
                authorized = True
            except Exception:
                authorized = False

    if not authorized and actor.password_hash is not None:
        if current_password and verify_password(current_password, actor.password_hash):
            authorized = True
    if not authorized and actor.password_hash is None:
        # Initial password assignment requires an active, non-expired session belonging to actor_id
        if session_id and session_token:
            sess = db.get(AuthSession, session_id)
            token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
            now_check = datetime.now(timezone.utc)
            if (
                sess is not None
                and sess.actor_id == actor_id
                and sess.revoked_at is None
                and sess.expires_at.replace(tzinfo=timezone.utc) > now_check
                and hmac.compare_digest(sess.token_hash, token_hash)
            ):
                authorized = True

    if not authorized:
        record_audit_event(
            db,
            actor_id=operator_actor_id or actor_id,
            action="auth:password:set",
            target=actor_id,
            decision="DENY",
            reason="Unauthorized password assignment or replacement attempt",
            correlation_id=correlation_id,
        )
        raise PermissionError("Unauthorized password assignment or replacement")

    actor.password_hash = hash_password(password)
    now = datetime.now(timezone.utc)
    active_sessions = (
        db.execute(
            select(AuthSession).where(
                AuthSession.actor_id == actor_id,
                AuthSession.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for sess in active_sessions:
        sess.revoked_at = now
        sess.revocation_reason = "Password changed"

    db.commit()
    db.refresh(actor)
    record_audit_event(
        db,
        actor_id=operator_actor_id or actor_id,
        action="auth:password:set",
        target=actor_id,
        decision="ALLOW",
        reason="Salted scrypt password hash updated and existing sessions revoked",
        correlation_id=correlation_id,
    )
    return actor


def authenticate_with_password(
    db: Session,
    *,
    actor_id: str,
    password: str,
    device_id: str,
    peer_id: str,
    ttl_seconds: int | None,
    correlation_id: str,
) -> tuple[AuthSession, str]:
    """Authenticate an actor with salted scrypt password verification, rate limiting, and session issuance."""
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=_LOGIN_WINDOW_SECONDS)
    with _LOGIN_FAIL_LOCK:
        recent = [ts for ts in _LOGIN_FAIL_WINDOWS.get(actor_id, []) if ts >= cutoff]
        _LOGIN_FAIL_WINDOWS[actor_id] = recent
        if len(recent) >= _LOGIN_MAX_FAILURES:
            record_audit_event(
                db,
                actor_id=actor_id,
                action="auth:login:rate_limited",
                target=device_id,
                decision="DENY",
                reason="Too many failed login attempts",
                correlation_id=correlation_id,
            )
            raise PermissionError("Too many failed login attempts")

    actor = db.get(Actor, actor_id)
    if actor is None or not actor.enabled or not verify_password(password, actor.password_hash):
        with _LOGIN_FAIL_LOCK:
            _LOGIN_FAIL_WINDOWS.setdefault(actor_id, []).append(now)
        record_audit_event(
            db,
            actor_id=actor_id,
            action="auth:login:password",
            target=device_id,
            decision="DENY",
            reason="Invalid actor credentials or disabled identity",
            correlation_id=correlation_id,
        )
        raise DomainValidationError("Invalid credentials")

    with _LOGIN_FAIL_LOCK:
        _LOGIN_FAIL_WINDOWS.pop(actor_id, None)
    return create_session(
        db,
        actor_id=actor_id,
        device_id=device_id,
        peer_id=peer_id,
        ttl_seconds=ttl_seconds,
        correlation_id=correlation_id,
    )

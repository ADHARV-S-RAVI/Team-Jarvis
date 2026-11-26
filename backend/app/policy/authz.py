"""Nine-step fail-closed zero-trust authorization engine (TRD Section 8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.db.models import (
    Actor,
    AssurancePolicyConfig,
    AuthSession,
    Device,
    IdentityVerificationEvent,
    IncidentPolicyDenial,
    KeyMetadata,
    Resource,
    RevocationTombstone,
    RolePermission,
)

ACTIVE_KEY_STATES = {"ACTIVE", "ACTIVE_NEW"}
OWNER_SCOPED_ACTIONS = {"resource:read", "resource:write", "resource:delete"}
SENSITIVE_ASSURANCE_ACTIONS = {"resource:read", "resource:write", "resource:delete", "key:rotate", "device:replace"}


@dataclass(frozen=True)
class AuthzRequest:
    """Inputs to the 9-step authorization pipeline."""

    actor_id: str
    session_id: str
    device_id: str
    resource_id: str
    action: str
    peer_id: str | None = None
    session_token: str | None = None
    in_flight: bool = False
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass(frozen=True)
class AuthzDecision:
    """Structured authorization decision with reason code and step trace."""

    decision: str  # "ALLOW" or "DENY"
    reason_code: str
    failed_step: int | None
    checks_passed: list[str]
    correlation_id: str


def _deny(
    reason_code: str,
    failed_step: int,
    checks_passed: list[str],
    correlation_id: str,
) -> AuthzDecision:
    return AuthzDecision(
        decision="DENY",
        reason_code=reason_code,
        failed_step=failed_step,
        checks_passed=checks_passed,
        correlation_id=correlation_id,
    )


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _has_tombstone(db: Session, subject_type: str, subject_id: str) -> bool:
    stmt = select(RevocationTombstone.id).where(
        RevocationTombstone.subject_type == subject_type,
        RevocationTombstone.subject_id == subject_id,
    ).limit(1)
    return db.execute(stmt).scalar_one_or_none() is not None


def evaluate_authorization(db: Session, req: AuthzRequest) -> AuthzDecision:
    """
    Execute the exact 9-step server-side authorization pipeline (fail closed).

    Steps:
    1. Parse and validate request.
    2. Identity exists and is enabled.
    3. Authenticated session is valid and bound to the identity.
    4. Session is not expired or revoked.
    5. Device belongs to actor, is enrolled/trusted and not revoked.
    6. Actor has permission for the resource/action.
    7. Resource exists and is not disabled.
    8. Key version is active and not revoked/compromised.
    9. Incident or policy does not deny.
    """
    passed: list[str] = []
    cid = req.correlation_id or str(uuid.uuid4())

    try:
        # Step 1: Parse and validate request
        if (
            not isinstance(req.actor_id, str) or not req.actor_id.strip()
            or not isinstance(req.session_id, str) or not req.session_id.strip()
            or not isinstance(req.device_id, str) or not req.device_id.strip()
            or not isinstance(req.resource_id, str) or not req.resource_id.strip()
            or not isinstance(req.action, str) or not req.action.strip()
        ):
            return _deny("INVALID_REQUEST", 1, passed, cid)
        passed.append("1_request_valid")

        # Step 2: Identity exists and is enabled (and not tombstoned)
        actor = db.get(Actor, req.actor_id)
        if actor is None:
            return _deny("IDENTITY_NOT_FOUND", 2, passed, cid)
        if not actor.enabled or _has_tombstone(db, "actor", actor.id):
            return _deny("IDENTITY_DISABLED_OR_REVOKED", 2, passed, cid)
        passed.append("2_identity_active")

        # Step 3: Authenticated session is valid and bound to the identity (and peer if provided)
        session = db.get(AuthSession, req.session_id)
        if session is None:
            return _deny("SESSION_NOT_FOUND", 3, passed, cid)
        if session.actor_id != actor.id:
            return _deny("SESSION_ACTOR_MISMATCH", 3, passed, cid)
        if req.session_token is not None:
            presented_hash = hashlib.sha256(req.session_token.encode("utf-8")).hexdigest()
            if session.token_hash != presented_hash:
                return _deny("SESSION_TOKEN_INVALID", 3, passed, cid)
        if req.peer_id is not None and session.peer_id != req.peer_id:
            return _deny("SESSION_PEER_MISMATCH", 3, passed, cid)
        passed.append("3_session_bound")

        # Step 4: Session is not expired or revoked
        now = datetime.now(timezone.utc)
        if session.revoked_at is not None or _has_tombstone(db, "session", session.id):
            return _deny("SESSION_REVOKED", 4, passed, cid)
        if _as_utc(session.expires_at) <= now:
            return _deny("SESSION_EXPIRED", 4, passed, cid)
        passed.append("4_session_active")

        # Step 5: Device belongs to actor, is enrolled/trusted, bound to session, and not revoked
        device = db.get(Device, req.device_id)
        if device is None:
            return _deny("DEVICE_NOT_FOUND", 5, passed, cid)
        if device.owner_actor_id != actor.id:
            return _deny("DEVICE_OWNERSHIP_MISMATCH", 5, passed, cid)
        if session.device_id != device.id:
            return _deny("SESSION_DEVICE_MISMATCH", 5, passed, cid)
        if device.state != "TRUSTED" or _has_tombstone(db, "device", device.id):
            return _deny("DEVICE_NOT_TRUSTED", 5, passed, cid)
        passed.append("5_device_trusted")

        # Step 6: Actor has permission for the resource/action
        perm_stmt = select(RolePermission.id).where(
            RolePermission.role == actor.role,
            RolePermission.permission == req.action,
        ).limit(1)
        if db.execute(perm_stmt).scalar_one_or_none() is None:
            return _deny("PERMISSION_DENIED", 6, passed, cid)

        # Step 7 (resource lookup needed for ownership/state, evaluated strictly in order):
        # First verify ownership boundary for owner-scoped actions without leaking existence
        resource = db.get(Resource, req.resource_id)
        if req.action in OWNER_SCOPED_ACTIONS:
            if resource is None or resource.owner_actor_id != actor.id:
                return _deny("RESOURCE_OWNERSHIP_DENIED", 6, passed, cid)
        passed.append("6_permission_granted")

        # Step 7: Resource exists and is not disabled
        if resource is None:
            return _deny("RESOURCE_NOT_FOUND", 7, passed, cid)
        if resource.state != "ACTIVE":
            return _deny("RESOURCE_DISABLED", 7, passed, cid)
        passed.append("7_resource_active")

        # Step 8: Key version is active and not revoked/compromised
        # Default zero grace period: RETIRED keys only permitted when explicitly classified in_flight=True
        key_stmt = select(KeyMetadata).where(KeyMetadata.version == resource.key_version).limit(1)
        key_meta = db.execute(key_stmt).scalar_one_or_none()
        if key_meta is None:
            return _deny("KEY_VERSION_NOT_FOUND", 8, passed, cid)
        if _has_tombstone(db, "key", key_meta.id) or key_meta.state in {"REVOKED", "COMPROMISED"}:
            return _deny("KEY_VERSION_INACTIVE_OR_REVOKED", 8, passed, cid)
        if key_meta.state not in ACTIVE_KEY_STATES:
            if not (req.in_flight and key_meta.state == "RETIRED"):
                return _deny("KEY_VERSION_INACTIVE_OR_REVOKED", 8, passed, cid)
        passed.append("8_key_active")

        # Step 9: Incident or policy does not deny
        subjects = [
            ("actor", actor.id),
            ("device", device.id),
            ("resource", resource.id),
            ("key", key_meta.id),
        ]
        for stype, sid in subjects:
            denial_stmt = select(IncidentPolicyDenial.id).where(
                IncidentPolicyDenial.subject_type == stype,
                IncidentPolicyDenial.subject_id == sid,
                IncidentPolicyDenial.active.is_(True),
            ).limit(1)
            if db.execute(denial_stmt).scalar_one_or_none() is not None:
                return _deny("INCIDENT_POLICY_DENIED", 9, passed, cid)

        # Stage 13 Identity Assurance Policy Check (inside Step 9 policy enforcement)
        policy_cfg = db.get(AssurancePolicyConfig, "default")
        if policy_cfg is not None:
            requires_webauthn = (
                policy_cfg.policy_mode == "REQUIRED_AFTER_LOGIN"
                or (policy_cfg.policy_mode == "REQUIRED_FOR_SENSITIVE_ACTIONS" and req.action in SENSITIVE_ASSURANCE_ACTIONS)
            )
            if requires_webauthn:
                latest_ev = db.execute(
                    select(IdentityVerificationEvent)
                    .where(
                        IdentityVerificationEvent.actor_id == actor.id,
                        IdentityVerificationEvent.verification_status == "SUCCESS",
                        IdentityVerificationEvent.assurance_level == "WEBAUTHN_ELEVATED",
                    )
                    .order_by(IdentityVerificationEvent.created_at.desc())
                    .limit(1)
                ).scalar_one_or_none()
                if latest_ev is None or latest_ev.fresh_until is None or _as_utc(latest_ev.fresh_until) <= now:
                    return _deny("IDENTITY_ASSURANCE_REQUIRED", 9, passed, cid)

        passed.append("9_policy_clear")

        return AuthzDecision(
            decision="ALLOW",
            reason_code="AUTHORIZED",
            failed_step=None,
            checks_passed=passed,
            correlation_id=cid,
        )
    except Exception:
        # Fail closed on any unexpected DB or runtime error
        return AuthzDecision(
            decision="DENY",
            reason_code="POLICY_EVALUATION_ERROR",
            failed_step=None,
            checks_passed=passed,
            correlation_id=cid,
        )

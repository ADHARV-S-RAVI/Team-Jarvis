"""WebAuthn / Passkey Identity Assurance, freshness policy, and device revocation integration."""

from __future__ import annotations

import base64
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import time
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from backend.app.audit.service import append_audit_event
from backend.app.db.models import (
    Actor,
    AssurancePolicyConfig,
    Device,
    IdentityCredential,
    IdentityVerificationEvent,
    Incident,
    RevocationTombstone,
    WebAuthnChallenge,
)
from backend.app.devices.service import DomainPermissionError, _require_operator
from backend.app.services.foundation_service import DomainNotFoundError, DomainValidationError
from backend.app.telemetry.bus import telemetry_bus

ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://localhost:5173",
    "https://127.0.0.1:5173",
]
ALLOWED_RP_IDS = {"localhost", "127.0.0.1"}
POLICY_MODES = {"OPTIONAL", "REQUIRED_FOR_SENSITIVE_ACTIONS", "REQUIRED_AFTER_LOGIN"}
CHALLENGE_TTL_SECONDS = 120

# In-memory sliding window rate limiter for failed verification attempts
_FAILED_ATTEMPTS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=20))
RATE_LIMIT_MAX_FAILS = 5
RATE_LIMIT_WINDOW_S = 60.0


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _check_actor_not_revoked(db: Session, actor_id: str) -> Actor:
    actor = db.get(Actor, actor_id)
    if actor is None or not actor.enabled:
        raise DomainPermissionError("Authentication denied")
    tomb = db.execute(
        select(RevocationTombstone.id)
        .where(RevocationTombstone.subject_type == "actor", RevocationTombstone.subject_id == actor_id)
        .limit(1)
    ).scalar_one_or_none()
    if tomb is not None:
        raise DomainPermissionError("Authentication denied")
    return actor


def _check_rate_limit(actor_id: str) -> None:
    now = time.monotonic()
    q = _FAILED_ATTEMPTS[actor_id]
    while q and now - q[0] > RATE_LIMIT_WINDOW_S:
        q.popleft()
    if len(q) >= RATE_LIMIT_MAX_FAILS:
        raise DomainPermissionError("Too many failed identity verification attempts; temporarily throttled")


def _record_failure(
    db: Session,
    *,
    actor_id: str,
    credential_id: str | None,
    device_id: str | None,
    reason: str,
    status_label: str = "FAILED",
    correlation_id: str = "id-verify-fail",
) -> None:
    _FAILED_ATTEMPTS[actor_id].append(time.monotonic())
    db.add(
        IdentityVerificationEvent(
            actor_id=actor_id,
            credential_id=credential_id,
            device_id=device_id,
            verification_method="WEBAUTHN_PLATFORM",
            verification_status=status_label,
            assurance_level="NONE",
            reason=reason[:250],
            correlation_id=correlation_id,
        )
    )
    append_audit_event(
        db,
        actor_id=actor_id,
        action="identity:webauthn:verify_failed",
        target=credential_id or actor_id,
        decision="DENY",
        reason=reason[:250],
        correlation_id=correlation_id,
    )
    # Escalate repeated failures to Incident Center
    if len(_FAILED_ATTEMPTS[actor_id]) >= 3:
        db.add(
            Incident(
                incident_type="IDENTITY_REPEATED_FAILURE",
                severity="HIGH",
                status="OPEN",
                initiator_actor_id="identity-assurance",
                target_subject_type="actor",
                target_subject_id=actor_id,
                reason=f"Repeated identity verification failures ({len(_FAILED_ATTEMPTS[actor_id])}x): {reason[:120]}",
                confirmed=False,
            )
        )
    db.commit()


def clear_rate_limit_for_test(actor_id: str | None = None) -> None:
    if actor_id:
        _FAILED_ATTEMPTS.pop(actor_id, None)
    else:
        _FAILED_ATTEMPTS.clear()


def get_or_init_policy(db: Session) -> AssurancePolicyConfig:
    cfg = db.get(AssurancePolicyConfig, "default")
    if cfg is None:
        cfg = AssurancePolicyConfig(
            id="default",
            policy_mode="OPTIONAL",
            freshness_window_seconds=300,
            require_user_verification=True,
            updated_by="system",
        )
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def update_policy(
    db: Session,
    *,
    operator_actor_id: str,
    policy_mode: str,
    freshness_window_seconds: int,
    require_user_verification: bool = True,
    correlation_id: str = "policy-update",
) -> AssurancePolicyConfig:
    _require_operator(db, operator_actor_id)
    if policy_mode not in POLICY_MODES:
        raise DomainValidationError(f"Unsupported policy_mode; expected one of {sorted(POLICY_MODES)}")
    if freshness_window_seconds < 10 or freshness_window_seconds > 86400:
        raise DomainValidationError("freshness_window_seconds must be between 10 and 86400")

    cfg = get_or_init_policy(db)
    cfg.policy_mode = policy_mode
    cfg.freshness_window_seconds = freshness_window_seconds
    cfg.require_user_verification = require_user_verification
    cfg.updated_by = operator_actor_id
    cfg.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(cfg)

    append_audit_event(
        db,
        actor_id=operator_actor_id,
        action="identity:assurance_policy:update",
        target="default",
        decision="ALLOW",
        reason=f"mode={policy_mode} freshness={freshness_window_seconds}s uv={require_user_verification}",
        correlation_id=correlation_id,
    )
    return cfg


def has_fresh_assurance(db: Session, actor_id: str) -> tuple[bool, IdentityVerificationEvent | None]:
    now = datetime.now(timezone.utc)
    latest = db.execute(
        select(IdentityVerificationEvent)
        .where(
            IdentityVerificationEvent.actor_id == actor_id,
            IdentityVerificationEvent.verification_status == "SUCCESS",
            IdentityVerificationEvent.assurance_level == "WEBAUTHN_ELEVATED",
        )
        .order_by(IdentityVerificationEvent.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()
    if latest is None or latest.fresh_until is None:
        return False, latest
    return _as_utc(latest.fresh_until) > now, latest


def _create_challenge(db: Session, *, actor_id: str, purpose: str) -> tuple[WebAuthnChallenge, bytes]:
    raw = os.urandom(32)
    ch_hash = hashlib.sha256(raw).hexdigest()
    now = datetime.now(timezone.utc)
    rec = WebAuthnChallenge(
        actor_id=actor_id,
        challenge_b64=base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        challenge_hash=ch_hash,
        purpose=purpose,
        expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS),
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec, raw


def _consume_challenge(
    db: Session,
    *,
    challenge_id: str,
    actor_id: str,
    purpose: str,
) -> bytes:
    rec = db.get(WebAuthnChallenge, challenge_id)
    if rec is None or rec.actor_id != actor_id or rec.purpose != purpose:
        raise DomainValidationError("Invalid WebAuthn challenge reference")
    if rec.consumed_at is not None:
        raise DomainValidationError("WebAuthn challenge already consumed (replay rejected)")
    now = datetime.now(timezone.utc)
    if _as_utc(rec.expires_at) <= now:
        rec.consumed_at = now
        db.commit()
        raise DomainValidationError("WebAuthn challenge expired")

    rec.consumed_at = now
    db.commit()
    padded = rec.challenge_b64 + "=" * (-len(rec.challenge_b64) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def generate_register_options(
    db: Session,
    *,
    actor_id: str,
    rp_id: str = "localhost",
) -> dict[str, object]:
    if rp_id not in ALLOWED_RP_IDS:
        raise DomainValidationError("RP ID not permitted")
    actor = _check_actor_not_revoked(db, actor_id)
    policy = get_or_init_policy(db)
    rec, raw_challenge = _create_challenge(db, actor_id=actor_id, purpose="register")

    opts = webauthn.generate_registration_options(
        rp_id=rp_id,
        rp_name="Q-SHIELD Control Plane",
        user_id=actor.id.encode("utf-8"),
        user_name=actor.id,
        user_display_name=actor.display_label,
        challenge=raw_challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=(
                UserVerificationRequirement.REQUIRED
                if policy.require_user_verification
                else UserVerificationRequirement.PREFERRED
            )
        ),
    )
    return {
        "challenge_id": rec.id,
        "expires_at": rec.expires_at.isoformat(),
        "options": json.loads(webauthn.options_to_json(opts)),
    }


def verify_registration(
    db: Session,
    *,
    actor_id: str,
    challenge_id: str,
    credential_json: dict[str, object],
    device_id: str | None = None,
    rp_id: str = "localhost",
    origin: str = "http://localhost:5173",
    correlation_id: str = "webauthn-reg",
) -> IdentityCredential:
    if rp_id not in ALLOWED_RP_IDS:
        raise DomainValidationError("RP ID not permitted")
    if origin not in ALLOWED_ORIGINS:
        raise DomainValidationError("Origin not permitted")
    _check_actor_not_revoked(db, actor_id)

    if device_id:
        dev = db.get(Device, device_id)
        if dev is None or dev.owner_actor_id != actor_id or dev.state != "TRUSTED":
            raise DomainPermissionError("Bound device is invalid or revoked")

    expected_challenge = _consume_challenge(db, challenge_id=challenge_id, actor_id=actor_id, purpose="register")
    policy = get_or_init_policy(db)

    try:
        verified = webauthn.verify_registration_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            require_user_verification=policy.require_user_verification,
        )
    except Exception as exc:
        _record_failure(db, actor_id=actor_id, credential_id=None, device_id=device_id, reason=f"Registration failed: {type(exc).__name__}", correlation_id=correlation_id)
        raise DomainPermissionError(f"WebAuthn registration verification failed: {type(exc).__name__}") from exc

    cred_id_b64 = base64.urlsafe_b64encode(verified.credential_id).decode("ascii").rstrip("=")
    pub_b64 = base64.b64encode(verified.credential_public_key).decode("ascii")
    meta = {
        "aaguid": str(verified.aaguid),
        "device_type": str(verified.credential_device_type),
        "backed_up": bool(verified.credential_backed_up),
        "user_verified": bool(verified.user_verified),
    }

    cred = IdentityCredential(
        actor_id=actor_id,
        device_id=device_id,
        credential_id=cred_id_b64,
        public_key_b64=pub_b64,
        sign_count=verified.sign_count,
        authenticator_metadata=json.dumps(meta, sort_keys=True),
        credential_status="ACTIVE",
    )
    db.add(cred)
    db.commit()
    db.refresh(cred)

    append_audit_event(
        db,
        actor_id=actor_id,
        action="identity:webauthn:register",
        target=cred.id,
        decision="ALLOW",
        reason=f"IDENTITY CREDENTIAL REGISTERED (device={device_id or 'unbound'})",
        correlation_id=correlation_id,
    )
    telemetry_bus.publish("credential_registered", {"actor_id": actor_id, "credential_id": cred.id})
    return cred


def generate_authenticate_options(
    db: Session,
    *,
    actor_id: str,
    rp_id: str = "localhost",
) -> dict[str, object]:
    if rp_id not in ALLOWED_RP_IDS:
        raise DomainValidationError("RP ID not permitted")
    _check_actor_not_revoked(db, actor_id)
    _check_rate_limit(actor_id)

    creds = list(
        db.execute(
            select(IdentityCredential).where(
                IdentityCredential.actor_id == actor_id,
                IdentityCredential.credential_status == "ACTIVE",
            )
        )
        .scalars()
        .all()
    )
    if not creds:
        raise DomainNotFoundError("No active WebAuthn credential enrolled for actor")

    descriptors = []
    for c in creds:
        padded = c.credential_id + "=" * (-len(c.credential_id) % 4)
        descriptors.append(PublicKeyCredentialDescriptor(id=base64.urlsafe_b64decode(padded.encode("ascii"))))

    policy = get_or_init_policy(db)
    rec, raw_challenge = _create_challenge(db, actor_id=actor_id, purpose="authenticate")

    opts = webauthn.generate_authentication_options(
        rp_id=rp_id,
        challenge=raw_challenge,
        allow_credentials=descriptors,
        user_verification=(
            UserVerificationRequirement.REQUIRED
            if policy.require_user_verification
            else UserVerificationRequirement.PREFERRED
        ),
    )
    return {
        "challenge_id": rec.id,
        "expires_at": rec.expires_at.isoformat(),
        "options": json.loads(webauthn.options_to_json(opts)),
    }


def verify_authentication(
    db: Session,
    *,
    actor_id: str,
    challenge_id: str,
    credential_json: dict[str, object],
    rp_id: str = "localhost",
    origin: str = "http://localhost:5173",
    correlation_id: str = "webauthn-auth",
) -> IdentityVerificationEvent:
    if rp_id not in ALLOWED_RP_IDS:
        raise DomainValidationError("RP ID not permitted")
    if origin not in ALLOWED_ORIGINS:
        raise DomainValidationError("Origin not permitted")
    _check_actor_not_revoked(db, actor_id)
    _check_rate_limit(actor_id)

    cred_raw_id = str(credential_json.get("id") or "")
    cred = db.execute(
        select(IdentityCredential).where(IdentityCredential.credential_id == cred_raw_id)
    ).scalar_one_or_none()
    if cred is None or cred.actor_id != actor_id:
        _record_failure(db, actor_id=actor_id, credential_id=cred_raw_id, device_id=None, reason="Unknown or mismatched credential", correlation_id=correlation_id)
        raise DomainPermissionError("Authentication failed")
    if cred.credential_status != "ACTIVE":
        _record_failure(db, actor_id=actor_id, credential_id=cred.credential_id, device_id=cred.device_id, reason="Credential is revoked", status_label="REVOKED_REJECTED", correlation_id=correlation_id)
        raise DomainPermissionError("Credential is revoked")

    # Enforce bound device trust: a revoked device cannot authenticate via WebAuthn
    if cred.device_id:
        dev = db.get(Device, cred.device_id)
        tomb = db.execute(
            select(RevocationTombstone.id)
            .where(RevocationTombstone.subject_type == "device", RevocationTombstone.subject_id == cred.device_id)
            .limit(1)
        ).scalar_one_or_none()
        if dev is None or dev.state != "TRUSTED" or tomb is not None:
            _record_failure(db, actor_id=actor_id, credential_id=cred.credential_id, device_id=cred.device_id, reason="Associated device is revoked", status_label="REVOKED_REJECTED", correlation_id=correlation_id)
            raise DomainPermissionError("Associated device is revoked")

    try:
        expected_challenge = _consume_challenge(db, challenge_id=challenge_id, actor_id=actor_id, purpose="authenticate")
    except DomainValidationError as exc:
        st_lbl = "EXPIRED" if "expired" in str(exc).lower() else "FAILED"
        _record_failure(db, actor_id=actor_id, credential_id=cred.credential_id, device_id=cred.device_id, reason=str(exc), status_label=st_lbl, correlation_id=correlation_id)
        raise DomainPermissionError("Challenge invalid or expired") from exc

    policy = get_or_init_policy(db)
    pub_bytes = base64.b64decode(cred.public_key_b64.encode("ascii"))

    try:
        verified = webauthn.verify_authentication_response(
            credential=credential_json,
            expected_challenge=expected_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=pub_bytes,
            credential_current_sign_count=cred.sign_count,
            require_user_verification=policy.require_user_verification,
        )
    except Exception as exc:
        _record_failure(db, actor_id=actor_id, credential_id=cred.credential_id, device_id=cred.device_id, reason=f"Assertion invalid: {type(exc).__name__}", correlation_id=correlation_id)
        raise DomainPermissionError("WebAuthn authentication verification failed") from exc

    now = datetime.now(timezone.utc)
    cred.sign_count = verified.new_sign_count
    cred.last_used_at = now
    fresh_until = now + timedelta(seconds=policy.freshness_window_seconds)

    ev = IdentityVerificationEvent(
        actor_id=actor_id,
        credential_id=cred.credential_id,
        device_id=cred.device_id,
        verification_method="WEBAUTHN_PLATFORM",
        verification_status="SUCCESS",
        assurance_level="WEBAUTHN_ELEVATED",
        fresh_until=fresh_until,
        reason="Platform authenticator cryptographic assertion verified",
        correlation_id=correlation_id,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)

    append_audit_event(
        db,
        actor_id=actor_id,
        action="identity:webauthn:authenticated",
        target=cred.id,
        decision="ALLOW",
        reason=f"WEBAUTHN_ELEVATED valid until {fresh_until.isoformat()}",
        correlation_id=correlation_id,
    )
    telemetry_bus.publish("identity_verified", {"actor_id": actor_id, "assurance_level": "WEBAUTHN_ELEVATED"})
    return ev


def revoke_or_remove_credential(
    db: Session,
    *,
    credential_record_id: str,
    actor_id: str,
    reason: str,
    delete_record: bool = False,
    correlation_id: str = "cred-revoke",
) -> dict[str, object]:
    cred = db.get(IdentityCredential, credential_record_id)
    if cred is None:
        raise DomainNotFoundError("Credential not found")
    # Owner or operator check
    acting = db.get(Actor, actor_id)
    if acting is None or (cred.actor_id != actor_id and acting.role not in {"Security Operator", "Admin"}):
        raise DomainPermissionError("Not authorized to manage this credential")

    now = datetime.now(timezone.utc)
    if delete_record:
        db.delete(cred)
        action = "identity:webauthn:credential_deleted"
        status_out = "DELETED"
    else:
        cred.credential_status = "REVOKED"
        cred.revoked_at = now
        action = "identity:webauthn:credential_revoked"
        status_out = "REVOKED"
    db.commit()

    append_audit_event(
        db,
        actor_id=actor_id,
        action=action,
        target=credential_record_id,
        decision="ALLOW",
        reason=reason,
        correlation_id=correlation_id,
    )
    return {"id": credential_record_id, "status": status_out}


def record_admin_recovery(
    db: Session,
    *,
    operator_actor_id: str,
    target_actor_id: str,
    reason: str,
    correlation_id: str = "id-recovery",
) -> IdentityVerificationEvent:
    _require_operator(db, operator_actor_id)
    _check_actor_not_revoked(db, target_actor_id)
    policy = get_or_init_policy(db)
    now = datetime.now(timezone.utc)
    ev = IdentityVerificationEvent(
        actor_id=target_actor_id,
        verification_method="RECOVERY_ADMIN",
        verification_status="SUCCESS",
        assurance_level="WEBAUTHN_ELEVATED",
        fresh_until=now + timedelta(seconds=min(120, policy.freshness_window_seconds)),
        reason=f"Operator-verified recovery by {operator_actor_id}: {reason}",
        correlation_id=correlation_id,
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)

    append_audit_event(
        db,
        actor_id=operator_actor_id,
        action="identity:assurance:admin_recovery",
        target=target_actor_id,
        decision="ALLOW",
        reason=reason,
        correlation_id=correlation_id,
    )
    return ev


def record_camera_demo_event(
    db: Session,
    *,
    actor_id: str,
    state: str,  # STARTED | STOPPED | PERMISSION_DENIED
    correlation_id: str = "cam-demo",
) -> None:
    """Audit camera demonstration lifecycle ONLY; never receives frames or biometrics."""
    if state not in {"STARTED", "STOPPED", "PERMISSION_DENIED"}:
        raise DomainValidationError("Invalid camera demo state")
    db.add(
        IdentityVerificationEvent(
            actor_id=actor_id,
            verification_method="CAMERA_DEMO_VISUAL_ONLY",
            verification_status=state,
            assurance_level="DEMO_VISUAL_NON_AUTH",
            reason=f"Non-authenticating visual camera demo {state} (no frames/biometrics stored)",
            correlation_id=correlation_id,
        )
    )
    append_audit_event(
        db,
        actor_id=actor_id,
        action=f"identity:camera_demo:{state.lower()}",
        target=actor_id,
        decision="ALLOW",
        reason="Non-authenticating camera demo lifecycle event (zero media stored)",
        correlation_id=correlation_id,
    )
    db.commit()

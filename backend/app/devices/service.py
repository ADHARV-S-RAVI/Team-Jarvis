"""Device lifecycle management and lost-device incident workflow (Stage 4)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import (
    Actor,
    AuthSession,
    Device,
    IdentityCredential,
    Incident,
    IncidentReceipt,
    RevocationTombstone,
)
from backend.app.services.foundation_service import (
    DomainConflictError,
    DomainNotFoundError,
    DomainValidationError,
    record_audit_event,
)

OPERATOR_ROLES = {"Security Operator", "Admin"}


class DomainPermissionError(Exception):
    """Raised when an actor lacks authority to perform an operator action."""


class NodePropagationBoundary(Protocol):
    """Integration boundary for Stage 5 multi-node revocation propagation."""

    def propagate_revocation(
        self, subject_type: str, subject_id: str, reason: str
    ) -> dict[str, object]:
        """Trigger revocation propagation to simulated nodes."""


class PendingStage5NodeBoundary:
    """Default Stage 4 boundary stub before Stage 5 node simulator is wired."""

    def propagate_revocation(
        self, subject_type: str, subject_id: str, reason: str
    ) -> dict[str, object]:
        return {
            "status": "PENDING_STAGE_5_SIMULATOR",
            "subject_type": subject_type,
            "subject_id": subject_id,
            "propagated_nodes": 0,
        }


def _require_operator(db: Session, operator_actor_id: str) -> Actor:
    actor = db.get(Actor, operator_actor_id)
    if actor is None or not actor.enabled:
        raise DomainPermissionError("Operator identity does not exist or is disabled")
    has_tombstone = (
        db.execute(
            select(RevocationTombstone.id)
            .where(
                RevocationTombstone.subject_type == "actor",
                RevocationTombstone.subject_id == operator_actor_id,
            )
            .limit(1)
        ).scalar_one_or_none()
        is not None
    )
    if has_tombstone or actor.role not in OPERATOR_ROLES:
        raise DomainPermissionError("Actor is not authorized to perform operator actions")
    return actor


def _revoke_device_sessions(db: Session, device_id: str, now: datetime) -> int:
    sessions = (
        db.execute(
            select(AuthSession).where(
                AuthSession.device_id == device_id,
                AuthSession.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )
    for sess in sessions:
        sess.revoked_at = now
    return len(sessions)


def _has_device_tombstone(db: Session, device_id: str) -> bool:
    return (
        db.execute(
            select(RevocationTombstone.id)
            .where(
                RevocationTombstone.subject_type == "device",
                RevocationTombstone.subject_id == device_id,
            )
            .limit(1)
        ).scalar_one_or_none()
        is not None
    )


def enrol_device(
    db: Session,
    *,
    device_id: str,
    owner_actor_id: str,
    credential_fingerprint: str,
    state: str = "TRUSTED",
    correlation_id: str = "device-enrol",
) -> Device:
    """Enrol a device, rejecting reuse of any previously revoked credential fingerprint."""
    actor = db.get(Actor, owner_actor_id)
    if actor is None or not actor.enabled:
        raise DomainNotFoundError(f"Active owner identity '{owner_actor_id}' not found")
    if db.get(Device, device_id) is not None:
        raise DomainConflictError(f"Device '{device_id}' already exists")

    revoked_fp = (
        db.execute(
            select(Device.id)
            .where(
                Device.credential_fingerprint == credential_fingerprint,
                Device.state == "REVOKED",
            )
            .limit(1)
        ).scalar_one_or_none()
    )
    if revoked_fp is not None:
        raise DomainValidationError("Revoked credential fingerprint cannot be reactivated")

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
        action="device:enrol",
        target=device.id,
        decision="ALLOW",
        reason="ENROLLED",
        correlation_id=correlation_id,
        metadata={"state": state},
    )
    return device


def suspend_device(
    db: Session,
    *,
    device_id: str,
    operator_actor_id: str,
    reason: str,
    correlation_id: str,
) -> Device:
    """Suspend a TRUSTED or PENDING device (requires operator authority)."""
    _require_operator(db, operator_actor_id)
    device = db.get(Device, device_id)
    if device is None:
        raise DomainNotFoundError(f"Device '{device_id}' not found")
    if device.state == "REVOKED" or _has_device_tombstone(db, device_id):
        raise DomainValidationError("Revoked device cannot be suspended or modified")
    device.state = "SUSPENDED"
    device.state_version += 1
    device.revocation_reason = reason
    db.commit()
    db.refresh(device)
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="device:suspend",
        target=device.id,
        decision="ALLOW",
        reason=reason,
        correlation_id=correlation_id,
    )
    return device


def restore_device(
    db: Session,
    *,
    device_id: str,
    operator_actor_id: str,
    reason: str,
    correlation_id: str,
) -> Device:
    """Restore a SUSPENDED device to TRUSTED; strictly forbids reactivating REVOKED devices."""
    _require_operator(db, operator_actor_id)
    device = db.get(Device, device_id)
    if device is None:
        raise DomainNotFoundError(f"Device '{device_id}' not found")
    if device.state == "REVOKED" or _has_device_tombstone(db, device_id):
        raise DomainValidationError("Revoked device can never be reactivated")
    if device.state != "SUSPENDED":
        raise DomainValidationError(f"Only SUSPENDED devices can be restored (current={device.state})")

    device.state = "TRUSTED"
    device.state_version += 1
    device.revocation_reason = None
    db.commit()
    db.refresh(device)
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="device:restore",
        target=device.id,
        decision="ALLOW",
        reason=reason,
        correlation_id=correlation_id,
    )
    return device


def revoke_device(
    db: Session,
    *,
    device_id: str,
    operator_actor_id: str,
    reason: str,
    correlation_id: str,
) -> tuple[Device, RevocationTombstone, int]:
    """Durably revoke a device, commit tombstone, and invalidate all its active sessions."""
    _require_operator(db, operator_actor_id)
    device = db.get(Device, device_id)
    if device is None:
        raise DomainNotFoundError(f"Device '{device_id}' not found")

    now = datetime.now(timezone.utc)
    max_epoch = (
        db.execute(
            select(func.max(RevocationTombstone.epoch)).where(
                RevocationTombstone.subject_type == "device",
                RevocationTombstone.subject_id == device_id,
            )
        ).scalar_one_or_none()
        or 0
    )
    tombstone = RevocationTombstone(
        subject_type="device",
        subject_id=device_id,
        epoch=max_epoch + 1,
        reason=reason,
    )
    device.state = "REVOKED"
    device.state_version += 1
    device.revocation_reason = reason
    revoked_sessions = _revoke_device_sessions(db, device_id, now)
    bound_creds = db.execute(
        select(IdentityCredential).where(
            IdentityCredential.device_id == device_id,
            IdentityCredential.credential_status == "ACTIVE",
        )
    ).scalars().all()
    for cred in bound_creds:
        cred.credential_status = "REVOKED"
        cred.revoked_at = now
    db.add(tombstone)
    db.commit()
    db.refresh(device)
    db.refresh(tombstone)

    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="device:revoke",
        target=device.id,
        decision="REVOKED",
        reason=reason,
        correlation_id=correlation_id,
        metadata={"epoch": tombstone.epoch, "sessions_revoked": revoked_sessions},
    )
    return device, tombstone, revoked_sessions


def enrol_replacement_device(
    db: Session,
    *,
    owner_actor_id: str,
    lost_device_id: str,
    new_device_id: str,
    new_credential_fingerprint: str,
    correlation_id: str,
) -> Device:
    """Enrol a replacement device for an owner; never restores trust to the old device."""
    lost_device = db.get(Device, lost_device_id)
    if lost_device is None:
        raise DomainNotFoundError(f"Lost device '{lost_device_id}' not found")
    if lost_device.owner_actor_id != owner_actor_id:
        raise DomainPermissionError("Actor does not own the lost device")
    if lost_device.state != "REVOKED":
        raise DomainValidationError("Replacement enrolment requires the old device to be REVOKED")
    if new_credential_fingerprint == lost_device.credential_fingerprint:
        raise DomainValidationError("Replacement device cannot reuse revoked credential fingerprint")

    return enrol_device(
        db,
        device_id=new_device_id,
        owner_actor_id=owner_actor_id,
        credential_fingerprint=new_credential_fingerprint,
        state="TRUSTED",
        correlation_id=correlation_id,
    )


def report_lost_device(
    db: Session,
    *,
    operator_actor_id: str,
    device_id: str,
    reason: str,
    confirmed: bool,
    correlation_id: str,
    node_boundary: NodePropagationBoundary | None = None,
) -> tuple[Incident, IncidentReceipt, Device]:
    """
    Execute the 8-step lost-device incident workflow:
    1. Verify operator authority & confirmation.
    2. Commit revocation tombstone, device REVOKED state, and session invalidation before success.
    3. Trigger node propagation boundary.
    4. Produce Incident & proof-carrying IncidentReceipt linked to AuditEvent.
    """
    _require_operator(db, operator_actor_id)
    if not confirmed:
        raise DomainValidationError("Lost-device revocation requires explicit confirmation")

    device, tombstone, sessions_revoked = revoke_device(
        db,
        device_id=device_id,
        operator_actor_id=operator_actor_id,
        reason=reason,
        correlation_id=correlation_id,
    )

    from backend.app.nodes.service import SimulatedNodePropagationBoundary

    boundary = node_boundary or SimulatedNodePropagationBoundary(db, epoch=tombstone.epoch)
    node_result = boundary.propagate_revocation("device", device_id, reason)
    conv_ms = node_result.get("convergence_ms")
    node_status = str(node_result.get("status", "NOT_CONVERGED"))

    incident = Incident(
        incident_type="LOST_DEVICE",
        severity="HIGH",
        status="CONTAINED" if node_status == "CONVERGED" else "DEGRADED_NOT_CONVERGED",
        initiator_actor_id=operator_actor_id,
        target_subject_type="device",
        target_subject_id=device_id,
        reason=reason,
        confirmed=confirmed,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    audit_event = record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="incident:lost_device",
        target=device_id,
        decision="DENY_OLD_DEVICE",
        reason=reason,
        correlation_id=correlation_id,
        metadata={
            "incident_id": incident.id,
            "tombstone_epoch": tombstone.epoch,
            "sessions_revoked": sessions_revoked,
            "node_status": node_status,
        },
    )

    receipt = IncidentReceipt(
        incident_id=incident.id,
        policy_decision="CENTRAL_TOMBSTONE_COMMITTED_DENY",
        state_transition=f"device:{device_id}:REVOKED(v{device.state_version})",
        node_acks_json=json.dumps(node_result, separators=(",", ":")),
        convergence_ms=int(conv_ms) if isinstance(conv_ms, int) else None,
        verification=f"TOMBSTONE_DURABLE_{node_status}",
        audit_ref=audit_event.event_id,
    )
    db.add(receipt)
    db.commit()
    db.refresh(receipt)
    return incident, receipt, device

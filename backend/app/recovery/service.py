"""Durable rotation journal, 7-point crash injection, and idempotent recovery (Stage 6)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.backups.service import create_backup_manifest
from backend.app.crypto.provider import sha256_hex
from backend.app.db.models import (
    KeyMetadata,
    NodeAcknowledgement,
    RevocationTombstone,
    RotationJournal,
)
from backend.app.devices.service import _require_operator
from backend.app.keys.service import KeyMaterialStore, generate_key_version, get_active_key_metadata
from backend.app.nodes.service import ensure_default_nodes, reconcile_nodes, stage_key_version_on_nodes
from backend.app.services.foundation_service import (
    DomainNotFoundError,
    DomainValidationError,
    record_audit_event,
)

CRASH_INJECTION_POINTS = {
    "after_prepare",
    "after_backup",
    "after_node_partial_ack",
    "before_commit",
    "immediately_after_commit",
    "during_retirement",
    "after_revocation_tombstone",
}


class SimulatedCrashError(RuntimeError):
    """Deterministic crash injection error for testing recovery semantics."""

    def __init__(self, point: str, operation_id: str) -> None:
        super().__init__(f"Simulated crash at '{point}' for operation '{operation_id}'")
        self.point = point
        self.operation_id = operation_id


def compute_journal_integrity_hash(
    *,
    operation_id: str,
    previous_version: int,
    proposed_version: int,
    phase: str,
    committed: bool,
    actor_id: str,
    reason: str,
) -> str:
    canonical = json.dumps(
        {
            "operation_id": operation_id,
            "previous_version": previous_version,
            "proposed_version": proposed_version,
            "phase": phase,
            "committed": committed,
            "actor_id": actor_id,
            "reason": reason,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_hex(canonical)


def _update_journal(db: Session, journal: RotationJournal, *, phase: str, committed: bool | None = None) -> None:
    journal.phase = phase
    if committed is not None:
        journal.committed = committed
    journal.updated_at = datetime.now(timezone.utc)
    journal.integrity_hash = compute_journal_integrity_hash(
        operation_id=journal.operation_id,
        previous_version=journal.previous_version,
        proposed_version=journal.proposed_version,
        phase=journal.phase,
        committed=journal.committed,
        actor_id=journal.actor_id,
        reason=journal.reason,
    )
    db.commit()
    db.refresh(journal)


def run_journaled_rotation(
    db: Session,
    *,
    operator_actor_id: str,
    reason: str,
    retire_policy: str = "RETIRED",
    crash_at: str | None = None,
    key_store: KeyMaterialStore | None = None,
) -> RotationJournal:
    """Execute a journaled 4-phase rotation with optional deterministic crash injection."""
    _require_operator(db, operator_actor_id)
    if retire_policy not in {"RETIRED", "REVOKED"}:
        raise DomainValidationError("retire_policy must be RETIRED or REVOKED")
    if crash_at is not None and crash_at not in CRASH_INJECTION_POINTS:
        raise DomainValidationError(f"Unsupported crash_at point: {crash_at}")

    current_key = get_active_key_metadata(db)
    if current_key.state in {"REVOKED", "COMPROMISED"}:
        raise DomainValidationError("Cannot rotate from a REVOKED or COMPROMISED key")

    op_id = str(uuid.uuid4())
    new_key = generate_key_version(db, algorithm=current_key.algorithm, state="PREPARED", key_store=key_store)

    now = datetime.now(timezone.utc)
    journal = RotationJournal(
        operation_id=op_id,
        previous_version=current_key.version,
        proposed_version=new_key.version,
        phase="PREPARE",
        committed=False,
        retire_policy=retire_policy,
        actor_id=operator_actor_id,
        reason=reason,
        integrity_hash=compute_journal_integrity_hash(
            operation_id=op_id,
            previous_version=current_key.version,
            proposed_version=new_key.version,
            phase="PREPARE",
            committed=False,
            actor_id=operator_actor_id,
            reason=reason,
        ),
        started_at=now,
        updated_at=now,
    )
    db.add(journal)
    db.commit()

    if crash_at == "after_prepare":
        raise SimulatedCrashError("after_prepare", op_id)

    # Backup phase
    backup = create_backup_manifest(
        db, operator_actor_id=operator_actor_id, correlation_id=op_id, key_store=key_store
    )
    journal.evidence_refs_json = json.dumps({"backup_manifest_id": backup["manifest_id"]})
    _update_journal(db, journal, phase="BACKUP")
    if crash_at == "after_backup":
        raise SimulatedCrashError("after_backup", op_id)

    # Distribute phase (partial node acks)
    current_key.state = "ROTATING"
    _update_journal(db, journal, phase="DISTRIBUTE")
    nodes = ensure_default_nodes(db)
    first_node = nodes[0]
    first_node.accepted_key_version = new_key.version
    db.add(
        NodeAcknowledgement(
            operation_id=op_id,
            node_id=first_node.id,
            sequence=first_node.last_sequence,
            ack_at=datetime.now(timezone.utc),
            enforced_at=datetime.now(timezone.utc),
            delay_ms=first_node.delay_ms,
            result="STAGED_PARTIAL",
        )
    )
    db.commit()
    if crash_at == "after_node_partial_ack":
        raise SimulatedCrashError("after_node_partial_ack", op_id)

    node_res = stage_key_version_on_nodes(db, key_version=new_key.version, operation_id=op_id)
    if node_res["status"] != "CONVERGED":
        raise DomainValidationError("Rotation halted: simulated node NOT CONVERGED")

    if crash_at == "before_commit":
        raise SimulatedCrashError("before_commit", op_id)

    # Commit phase (atomic pointer update)
    commit_time = datetime.now(timezone.utc)
    new_key.state = "ACTIVE_NEW"
    new_key.activated_at = commit_time
    journal.committed_at = commit_time
    _update_journal(db, journal, phase="COMMIT", committed=True)
    if crash_at == "immediately_after_commit":
        raise SimulatedCrashError("immediately_after_commit", op_id)

    # Retirement phase
    _update_journal(db, journal, phase="RETIRE_IN_PROGRESS", committed=True)
    if crash_at == "during_retirement":
        raise SimulatedCrashError("during_retirement", op_id)

    current_key.state = retire_policy
    current_key.retired_at = datetime.now(timezone.utc)
    db.commit()

    if retire_policy == "REVOKED":
        db.add(
            RevocationTombstone(
                subject_type="key",
                subject_id=current_key.id,
                epoch=new_key.version,
                reason=f"Journaled rotation REVOKED: {reason}",
            )
        )
        db.commit()
    if crash_at == "after_revocation_tombstone":
        raise SimulatedCrashError("after_revocation_tombstone", op_id)

    _update_journal(db, journal, phase="COMPLETED", committed=True)
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="key:rotate_journaled",
        target=f"v{current_key.version}->v{new_key.version}",
        decision="COMMITTED",
        reason=reason,
        correlation_id=op_id,
    )
    return journal


def _is_key_revoked(db: Session, key_meta: KeyMetadata) -> bool:
    if key_meta.state in {"REVOKED", "COMPROMISED"}:
        return True
    ts = (
        db.execute(
            select(RevocationTombstone.id)
            .where(RevocationTombstone.subject_type == "key", RevocationTombstone.subject_id == key_meta.id)
            .limit(1)
        ).scalar_one_or_none()
    )
    return ts is not None


def recover_rotation_journal(
    db: Session,
    *,
    operation_id: str,
    operator_actor_id: str,
    correlation_id: str = "recovery",
) -> dict[str, object]:
    """
    Idempotently recover an interrupted rotation journal:
    - Verifies journal integrity hash first (fails closed on corruption).
    - Pre-commit: restores previous_version to ACTIVE unless superseded by revocation.
    - Post-commit: ensures proposed_version is ACTIVE_NEW and previous_version is retired/revoked.
    - Never reactivates REVOKED or COMPROMISED keys.
    """
    _require_operator(db, operator_actor_id)
    journal = db.get(RotationJournal, operation_id)
    if journal is None:
        raise DomainNotFoundError(f"Rotation journal '{operation_id}' not found")

    expected_hash = compute_journal_integrity_hash(
        operation_id=journal.operation_id,
        previous_version=journal.previous_version,
        proposed_version=journal.proposed_version,
        phase=journal.phase,
        committed=journal.committed,
        actor_id=journal.actor_id,
        reason=journal.reason,
    )
    if expected_hash != journal.integrity_hash:
        raise DomainValidationError("Corrupted rotation journal: integrity hash mismatch")

    if journal.phase in {"RECOVERED_PRE_COMMIT", "RECOVERED_POST_COMMIT", "COMPLETED"}:
        active = get_active_key_metadata(db)
        return {
            "operation_id": operation_id,
            "recovery_outcome": "IDEMPOTENT_ALREADY_RECOVERED",
            "phase": journal.phase,
            "committed": journal.committed,
            "active_key_version": active.version,
        }

    prev_key = db.execute(
        select(KeyMetadata).where(KeyMetadata.version == journal.previous_version)
    ).scalar_one_or_none()
    prop_key = db.execute(
        select(KeyMetadata).where(KeyMetadata.version == journal.proposed_version)
    ).scalar_one_or_none()
    if prev_key is None or prop_key is None:
        raise DomainValidationError("Inconsistent key metadata during recovery; fail closed")

    now = datetime.now(timezone.utc)
    if not journal.committed:
        # Pre-commit recovery: revert to previous_version unless superseded by revocation
        if _is_key_revoked(db, prev_key):
            prev_key.state = "REVOKED"
            prop_key.state = "RETIRED"
            journal.recovered_at = now
            _update_journal(db, journal, phase="RECOVERED_FAIL_CLOSED_REVOKED", committed=False)
            raise DomainValidationError("Pre-commit recovery blocked: previous key was revoked")

        prev_key.state = "ACTIVE"
        if not _is_key_revoked(db, prop_key):
            prop_key.state = "RETIRED"
        journal.recovered_at = now
        _update_journal(db, journal, phase="RECOVERED_PRE_COMMIT", committed=False)
        outcome = "RECOVERED_PRE_COMMIT"
        active_ver = prev_key.version
    else:
        # Post-commit recovery: ensure proposed_version is active (unless compromised) and old is retired/revoked
        if _is_key_revoked(db, prop_key):
            raise DomainValidationError("Post-commit recovery blocked: proposed key is revoked/compromised")
        prop_key.state = "ACTIVE_NEW"
        if not _is_key_revoked(db, prev_key):
            prev_key.state = journal.retire_policy
            prev_key.retired_at = prev_key.retired_at or now
            if journal.retire_policy == "REVOKED":
                db.add(
                    RevocationTombstone(
                        subject_type="key",
                        subject_id=prev_key.id,
                        epoch=prop_key.version,
                        reason=f"Post-commit recovery enforced REVOKED: {journal.reason}",
                    )
                )
        reconcile_nodes(db)
        journal.recovered_at = now
        _update_journal(db, journal, phase="RECOVERED_POST_COMMIT", committed=True)
        outcome = "RECOVERED_POST_COMMIT"
        active_ver = prop_key.version

    audit_ev = record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="recovery:rotation",
        target=operation_id,
        decision="ALLOW",
        reason=outcome,
        correlation_id=correlation_id,
        metadata={"active_key_version": active_ver, "committed": journal.committed},
    )
    return {
        "operation_id": operation_id,
        "recovery_outcome": outcome,
        "phase": journal.phase,
        "committed": journal.committed,
        "active_key_version": active_ver,
        "audit_ref": audit_ev.event_id,
    }

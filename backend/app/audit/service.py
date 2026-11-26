"""Append-only structured audit ledger, boundary protection, and chain verifier (Stage 7)."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
import threading
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import AuditEvent, Incident, IncidentReceipt

CANONICAL_VERSION = "v1"
GENESIS_HASH = "GENESIS"
MAX_TEXT_LEN = 256
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
_SENSITIVE_KEYS = {
    "token",
    "session_token",
    "secret",
    "shared_secret",
    "private_key",
    "key_material",
    "plaintext",
    "password",
    "dek",
    "kek",
    "master_key",
}
_AUDIT_LOCK = threading.RLock()


def sanitize_text(value: str, max_len: int = MAX_TEXT_LEN) -> str:
    """Normalize/escape CR/LF/control characters and cap length to prevent log injection."""
    return _CONTROL_CHAR_RE.sub("_", str(value))[:max_len]


def sanitize_metadata(metadata: dict[str, object] | None) -> dict[str, str | int | bool | None]:
    """Redact sensitive keys and sanitize all string values in structured metadata."""
    if not metadata:
        return {}
    clean: dict[str, str | int | bool | None] = {}
    for k, v in metadata.items():
        key_clean = sanitize_text(str(k), 64)
        if key_clean.lower() in _SENSITIVE_KEYS:
            clean[key_clean] = "[REDACTED]"
        elif isinstance(v, str):
            clean[key_clean] = sanitize_text(v)
        elif isinstance(v, (int, bool)) or v is None:
            clean[key_clean] = v
        else:
            clean[key_clean] = sanitize_text(str(v))
    return clean


def canonical_event_bytes(
    *,
    sequence: int,
    actor_id: str,
    action: str,
    target: str,
    decision: str,
    reason: str,
    correlation_id: str,
    metadata: dict[str, object],
) -> bytes:
    """Deterministic UTF-8 canonical serialization (v1) for SHA-256 hash chaining."""
    payload = {
        "sequence": sequence,
        "actor_id": actor_id,
        "action": action,
        "target": target,
        "decision": decision,
        "reason": reason,
        "correlation_id": correlation_id,
        "metadata": metadata,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_event_hash(prev_hash: str, canonical_bytes: bytes) -> str:
    """Compute SHA-256(prev_hash || canonical_event_bytes)."""
    return hashlib.sha256(prev_hash.encode("utf-8") + canonical_bytes).hexdigest()


def append_audit_event(
    db: Session,
    *,
    actor_id: str,
    action: str,
    target: str,
    decision: str,
    reason: str,
    correlation_id: str,
    metadata: dict[str, object] | None = None,
) -> AuditEvent:
    """Append a sanitized, hash-chained audit event (serialized for monotonic sequence)."""
    safe_actor = sanitize_text(actor_id, 64)
    safe_action = sanitize_text(action, 64)
    safe_target = sanitize_text(target, 128)
    safe_decision = sanitize_text(decision, 32)
    safe_reason = sanitize_text(reason, 128)
    safe_cid = sanitize_text(correlation_id, 64)
    safe_meta = sanitize_metadata(metadata)

    with _AUDIT_LOCK:
        max_seq = db.execute(select(func.max(AuditEvent.sequence))).scalar_one_or_none() or 0
        next_seq = max_seq + 1
        prev_event = db.execute(
            select(AuditEvent).where(AuditEvent.sequence == max_seq)
        ).scalar_one_or_none()
        prev_hash = prev_event.event_hash if prev_event and prev_event.event_hash else GENESIS_HASH

        c_bytes = canonical_event_bytes(
            sequence=next_seq,
            actor_id=safe_actor,
            action=safe_action,
            target=safe_target,
            decision=safe_decision,
            reason=safe_reason,
            correlation_id=safe_cid,
            metadata=safe_meta,
        )
        ev_hash = compute_event_hash(prev_hash, c_bytes)

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            sequence=next_seq,
            timestamp=datetime.now(timezone.utc),
            actor_id=safe_actor,
            action=safe_action,
            target=safe_target,
            decision=safe_decision,
            reason=safe_reason,
            correlation_id=safe_cid,
            metadata_json=json.dumps(safe_meta, sort_keys=True, separators=(",", ":")),
            prev_hash=prev_hash,
            event_hash=ev_hash,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event


def verify_audit_records(events: list[dict[str, object]]) -> dict[str, object]:
    """
    Verify an ordered list of audit event dicts for:
    - deletion (sequence gaps)
    - reordering (sequence / prev_hash mismatch)
    - modification & actor mutation (recomputed SHA-256 mismatch)
    - boundary/log injection (unescaped control characters)
    """
    failures: list[dict[str, object]] = []
    if not events:
        return {"valid": True, "checked_events": 0, "failures": []}

    expected_seq = 1
    expected_prev_hash = GENESIS_HASH

    for ev in events:
        seq = ev.get("sequence")
        ev_id = ev.get("event_id", "unknown")

        if seq != expected_seq:
            failures.append(
                {
                    "sequence": seq,
                    "event_id": ev_id,
                    "issue": f"SEQUENCE_GAP_OR_REORDER: expected {expected_seq}, got {seq}",
                }
            )
            if isinstance(seq, int):
                expected_seq = seq

        if ev.get("prev_hash") != expected_prev_hash:
            failures.append(
                {
                    "sequence": seq,
                    "event_id": ev_id,
                    "issue": "BROKEN_PREV_HASH_LINK",
                }
            )

        for field_name in ("actor_id", "action", "target", "decision", "reason"):
            val = str(ev.get(field_name, ""))
            if _CONTROL_CHAR_RE.search(val):
                failures.append(
                    {
                        "sequence": seq,
                        "event_id": ev_id,
                        "issue": f"BOUNDARY_INJECTION_IN_{field_name.upper()}",
                    }
                )

        meta_raw = ev.get("metadata_json", "{}")
        try:
            meta_obj = json.loads(meta_raw) if isinstance(meta_raw, str) else meta_raw
        except json.JSONDecodeError:
            meta_obj = {}
            failures.append(
                {
                    "sequence": seq,
                    "event_id": ev_id,
                    "issue": "CORRUPTED_METADATA_JSON",
                }
            )

        c_bytes = canonical_event_bytes(
            sequence=int(seq) if isinstance(seq, int) else -1,
            actor_id=str(ev.get("actor_id", "")),
            action=str(ev.get("action", "")),
            target=str(ev.get("target", "")),
            decision=str(ev.get("decision", "")),
            reason=str(ev.get("reason", "")),
            correlation_id=str(ev.get("correlation_id", "")),
            metadata=meta_obj if isinstance(meta_obj, dict) else {},
        )
        recomputed = compute_event_hash(str(ev.get("prev_hash", "")), c_bytes)
        if recomputed != ev.get("event_hash"):
            failures.append(
                {
                    "sequence": seq,
                    "event_id": ev_id,
                    "issue": "EVENT_HASH_MISMATCH_MODIFIED",
                }
            )

        expected_prev_hash = str(ev.get("event_hash", ""))
        expected_seq += 1

    return {
        "valid": len(failures) == 0,
        "checked_events": len(events),
        "canonical_version": CANONICAL_VERSION,
        "genesis": GENESIS_HASH,
        "failures": failures,
    }


def _to_record_dict(ev: AuditEvent) -> dict[str, object]:
    return {
        "event_id": ev.event_id,
        "sequence": ev.sequence,
        "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
        "actor_id": ev.actor_id,
        "action": ev.action,
        "target": ev.target,
        "decision": ev.decision,
        "reason": ev.reason,
        "correlation_id": ev.correlation_id,
        "metadata_json": ev.metadata_json,
        "prev_hash": ev.prev_hash,
        "event_hash": ev.event_hash,
    }


def verify_db_audit_chain(db: Session) -> dict[str, object]:
    """Verify the entire persisted audit_events table."""
    rows = list(db.execute(select(AuditEvent).order_by(AuditEvent.sequence.asc())).scalars().all())
    return verify_audit_records([_to_record_dict(r) for r in rows])


def search_audit_events(
    db: Session,
    *,
    actor_id: str | None = None,
    action: str | None = None,
    decision: str | None = None,
    correlation_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditEvent]:
    stmt = select(AuditEvent)
    if actor_id:
        stmt = stmt.where(AuditEvent.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if decision:
        stmt = stmt.where(AuditEvent.decision == decision)
    if correlation_id:
        stmt = stmt.where(AuditEvent.correlation_id == correlation_id)
    stmt = stmt.order_by(AuditEvent.sequence.asc()).offset(offset).limit(limit)
    return list(db.execute(stmt).scalars().all())


def get_correlation_timeline(db: Session, correlation_id: str) -> list[AuditEvent]:
    return list(
        db.execute(
            select(AuditEvent)
            .where(AuditEvent.correlation_id == correlation_id)
            .order_by(AuditEvent.sequence.asc())
        )
        .scalars()
        .all()
    )


def export_sanitized_audit(db: Session) -> dict[str, object]:
    rows = list(db.execute(select(AuditEvent).order_by(AuditEvent.sequence.asc())).scalars().all())
    records = [_to_record_dict(r) for r in rows]
    return {
        "canonical_version": CANONICAL_VERSION,
        "genesis": GENESIS_HASH,
        "hash_algorithm": "SHA-256",
        "ml_dsa_checkpoint_status": "DEFERRED_NOT_IMPLEMENTED",
        "verification": verify_audit_records(records),
        "events": records,
    }


def run_non_destructive_tamper_demo(db: Session) -> dict[str, object]:
    """
    Non-destructive tamper fixture: clones persisted events in memory, mutates actor_id
    on the first event, and runs verify_audit_records() to prove detection without altering DB.
    """
    rows = list(db.execute(select(AuditEvent).order_by(AuditEvent.sequence.asc())).scalars().all())
    if not rows:
        return {"demo": True, "skipped": True, "reason": "No audit events to demonstrate"}
    cloned = [_to_record_dict(r) for r in rows]
    cloned[0]["actor_id"] = "tampered-admin"
    result = verify_audit_records(cloned)
    return {
        "demo": True,
        "non_destructive": True,
        "tamper_type": "ACTOR_MUTATION",
        "detected": not result["valid"],
        "verification": result,
    }


def verify_incident_receipt_chain(db: Session, incident_id: str) -> dict[str, object]:
    """Verify an IncidentReceipt links to a valid AuditEvent in a verified chain."""
    incident = db.get(Incident, incident_id)
    receipt = db.execute(
        select(IncidentReceipt).where(IncidentReceipt.incident_id == incident_id)
    ).scalar_one_or_none()
    if incident is None or receipt is None:
        return {"valid": False, "reason": "INCIDENT_OR_RECEIPT_NOT_FOUND"}

    audit_ev = db.get(AuditEvent, receipt.audit_ref)
    chain_res = verify_db_audit_chain(db)
    valid = audit_ev is not None and bool(chain_res["valid"])
    return {
        "valid": valid,
        "incident_id": incident_id,
        "receipt_id": receipt.id,
        "audit_ref": receipt.audit_ref,
        "audit_event_found": audit_ev is not None,
        "chain_valid": chain_res["valid"],
    }

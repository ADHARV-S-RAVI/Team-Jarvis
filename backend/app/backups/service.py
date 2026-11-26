"""Integrity-protected backup manifest creation, verification, and safe restore (Stage 6)."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.crypto.provider import (
    hmac_sha256_hex,
    hmac_sha256_verify,
    sha256_hex,
)
from backend.app.db.models import BackupManifest, KeyMetadata, RevocationTombstone
from backend.app.devices.service import _require_operator
from backend.app.keys.service import KeyMaterialStore, get_active_key_metadata
from backend.app.services.foundation_service import DomainValidationError, record_audit_event


def _backup_hmac_key(key_store: KeyMaterialStore | None = None) -> bytes:
    store = key_store or KeyMaterialStore()
    return store.derive_wrapping_key(1, purpose="backup-manifest-auth")


def create_backup_manifest(
    db: Session,
    *,
    operator_actor_id: str,
    correlation_id: str = "backup-create",
    key_store: KeyMaterialStore | None = None,
) -> dict[str, object]:
    """Create an HMAC-SHA-256 authenticated and SHA-256 verified backup manifest."""
    _require_operator(db, operator_actor_id)
    active_key = get_active_key_metadata(db)
    all_keys = list(db.execute(select(KeyMetadata).order_by(KeyMetadata.version.asc())).scalars().all())
    max_epoch = db.execute(select(func.max(RevocationTombstone.epoch))).scalar_one_or_none() or 0

    keys_snapshot = [
        {
            "id": k.id,
            "version": k.version,
            "algorithm": k.algorithm,
            "state": k.state,
        }
        for k in all_keys
    ]
    payload_dict = {
        "schema_version": "v1",
        "backup_epoch": max_epoch,
        "active_key_version": active_key.version,
        "keys": keys_snapshot,
    }
    payload_json = json.dumps(payload_dict, sort_keys=True, separators=(",", ":"))
    manifest_sha256 = sha256_hex(payload_json.encode("utf-8"))
    hmac_hex = hmac_sha256_hex(_backup_hmac_key(key_store), payload_json.encode("utf-8"))

    manifest_id = str(uuid.uuid4())
    record = BackupManifest(
        id=manifest_id,
        backup_epoch=max_epoch,
        active_key_version=active_key.version,
        key_ids_json=json.dumps([k.id for k in all_keys], separators=(",", ":")),
        manifest_sha256=manifest_sha256,
        hmac_hex=hmac_hex,
        payload_json=payload_json,
        created_by=operator_actor_id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="backup:create",
        target=manifest_id,
        decision="ALLOW",
        reason="MANIFEST_CREATED",
        correlation_id=correlation_id,
        metadata={"backup_epoch": max_epoch, "active_key_version": active_key.version},
    )

    return {
        "manifest_id": manifest_id,
        "backup_epoch": max_epoch,
        "active_key_version": active_key.version,
        "manifest_sha256": manifest_sha256,
        "hmac_hex": hmac_hex,
        "payload": payload_dict,
    }


def verify_backup_manifest(
    db: Session,
    *,
    manifest: dict[str, object],
    key_store: KeyMaterialStore | None = None,
) -> tuple[bool, str]:
    """
    Verify completeness, SHA-256 digest, HMAC-SHA-256 authenticity, and freshness.
    Rejects incomplete, byte-tampered, wrong-key, and stale backups.
    """
    required = {"manifest_id", "backup_epoch", "active_key_version", "manifest_sha256", "hmac_hex", "payload"}
    if not required.issubset(manifest.keys()):
        return False, "BACKUP_INCOMPLETE"

    payload = manifest.get("payload")
    if not isinstance(payload, dict) or not {"backup_epoch", "active_key_version", "keys"}.issubset(payload.keys()):
        return False, "BACKUP_INCOMPLETE"

    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    computed_sha = sha256_hex(payload_json.encode("utf-8"))
    if computed_sha != manifest.get("manifest_sha256"):
        return False, "BACKUP_TAMPERED_DIGEST"

    expected_hmac = str(manifest.get("hmac_hex", ""))
    if not hmac_sha256_verify(_backup_hmac_key(key_store), payload_json.encode("utf-8"), expected_hmac):
        return False, "BACKUP_INVALID_HMAC_OR_WRONG_KEY"

    # Reject stale backups that would trail current revocation epoch or active key version
    current_max_epoch = db.execute(select(func.max(RevocationTombstone.epoch))).scalar_one_or_none() or 0
    backup_epoch = int(payload["backup_epoch"])
    if backup_epoch < current_max_epoch:
        return False, "BACKUP_STALE_REVOCATION_EPOCH"

    current_active = get_active_key_metadata(db)
    backup_active_ver = int(payload["active_key_version"])
    if backup_active_ver < current_active.version:
        return False, "BACKUP_STALE_KEY_VERSION"

    return True, "BACKUP_VERIFIED"


def restore_backup_manifest(
    db: Session,
    *,
    manifest: dict[str, object],
    operator_actor_id: str,
    correlation_id: str = "backup-restore",
    key_store: KeyMaterialStore | None = None,
) -> dict[str, object]:
    """
    Verify backup manifest before restore.
    - Rejects unverified, tampered, incomplete, wrong-key, or stale backups.
    - Never reactivates revoked/compromised keys or undoes revocation tombstones.
    - Idempotent on duplicate restore.
    """
    _require_operator(db, operator_actor_id)
    valid, reason = verify_backup_manifest(db, manifest=manifest, key_store=key_store)
    if not valid:
        record_audit_event(
            db,
            actor_id=operator_actor_id,
            action="backup:restore",
            target=str(manifest.get("manifest_id", "unknown")),
            decision="DENY",
            reason=reason,
            correlation_id=correlation_id,
        )
        raise DomainValidationError(f"Backup restore rejected: {reason}")

    payload = manifest["payload"]
    assert isinstance(payload, dict)
    restored_keys = 0
    for k_item in payload.get("keys", []):
        if not isinstance(k_item, dict):
            continue
        k_id = str(k_item["id"])
        existing = db.get(KeyMetadata, k_id)
        # Never reactivate REVOKED or COMPROMISED keys
        has_tombstone = (
            db.execute(
                select(RevocationTombstone.id)
                .where(RevocationTombstone.subject_type == "key", RevocationTombstone.subject_id == k_id)
                .limit(1)
            ).scalar_one_or_none()
            is not None
        )
        if existing is not None:
            if existing.state in {"REVOKED", "COMPROMISED"} or has_tombstone:
                continue
            restored_keys += 1
        else:
            state = "REVOKED" if has_tombstone else str(k_item["state"])
            db.add(
                KeyMetadata(
                    id=k_id,
                    version=int(k_item["version"]),
                    algorithm=str(k_item["algorithm"]),
                    state=state,
                    created_at=datetime.now(timezone.utc),
                )
            )
            restored_keys += 1

    db.commit()
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="backup:restore",
        target=str(manifest["manifest_id"]),
        decision="ALLOW",
        reason="BACKUP_RESTORED",
        correlation_id=correlation_id,
        metadata={"restored_keys": restored_keys},
    )
    return {
        "status": "RESTORED",
        "manifest_id": manifest["manifest_id"],
        "restored_keys": restored_keys,
    }

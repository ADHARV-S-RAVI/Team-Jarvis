"""Foundational key management separating KeyMetadata (DB) from secret key material (local store).

Note: Local file-backed key storage is a development-only mechanism and is NOT an HSM.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.config import get_settings
from backend.app.crypto.provider import (
    AES_256_KEY_BYTES,
    ALG_AES_256_GCM,
    AesGcmSealed,
    CryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_sha256,
    random_bytes,
)
from backend.app.db.models import KeyMetadata, RevocationTombstone, RotationOperation


class KeyMaterialStore:
    """Isolated local store for versioned symmetric KEKs, separate from SQLite metadata."""

    def __init__(self, store_dir: Path | None = None, master_key_b64: str | None = None) -> None:
        settings = get_settings()
        self.store_dir = store_dir or Path(settings.key_store_dir)
        self._env_master_key_b64 = master_key_b64 if master_key_b64 is not None else settings.master_key_b64
        self._master_key_path = self.store_dir / "master_kek.key"
        self._versions_path = self.store_dir / "key_versions.json"

    def _restrict_permissions(self, path: Path) -> None:
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

    def _atomic_write_text(self, path: Path, content: str) -> None:
        self.store_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".ks_", suffix=".tmp", dir=str(self.store_dir))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
            self._restrict_permissions(path)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    def _get_or_init_master_key(self) -> bytes:
        if self._env_master_key_b64:
            raw = base64.b64decode(self._env_master_key_b64.encode("ascii"), validate=True)
            if len(raw) != AES_256_KEY_BYTES:
                raise CryptoError("Configured master key must be 32 bytes")
            return raw

        if self._master_key_path.exists():
            raw = base64.b64decode(self._master_key_path.read_text(encoding="utf-8").strip(), validate=True)
            if len(raw) != AES_256_KEY_BYTES:
                raise CryptoError("Stored local master key has invalid length")
            return raw

        generated = random_bytes(AES_256_KEY_BYTES)
        self._atomic_write_text(self._master_key_path, base64.b64encode(generated).decode("ascii"))
        return generated

    def _load_versions_map(self) -> dict[str, dict[str, str]]:
        if not self._versions_path.exists():
            return {}
        data = json.loads(self._versions_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise CryptoError("Corrupted key versions store")
        return data

    def ensure_version_secret(self, version: int) -> bytes:
        """Return the 32-byte KEK for `version`, generating and wrapping it if absent."""
        master_key = self._get_or_init_master_key()
        versions = self._load_versions_map()
        vkey = str(version)
        aad = f"qshield:kek:v{version}".encode("utf-8")

        if vkey in versions:
            entry = versions[vkey]
            return aes_gcm_decrypt(
                master_key,
                nonce=base64.b64decode(entry["nonce_b64"], validate=True),
                ciphertext=base64.b64decode(entry["ciphertext_b64"], validate=True),
                tag=base64.b64decode(entry["tag_b64"], validate=True),
                aad=aad,
            )

        secret = random_bytes(AES_256_KEY_BYTES)
        sealed = aes_gcm_encrypt(master_key, secret, aad=aad)
        versions[vkey] = {
            "nonce_b64": base64.b64encode(sealed.nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(sealed.ciphertext).decode("ascii"),
            "tag_b64": base64.b64encode(sealed.tag).decode("ascii"),
        }
        self._atomic_write_text(self._versions_path, json.dumps(versions, separators=(",", ":")))
        return secret

    def derive_wrapping_key(self, version: int, *, purpose: str = "resource-dek-wrap") -> bytes:
        """Derive a purpose-separated 256-bit wrapping key for `version` via HKDF-SHA-256."""
        kek = self.ensure_version_secret(version)
        info = f"qshield:{purpose}:v{version}".encode("utf-8")
        return hkdf_sha256(kek, AES_256_KEY_BYTES, salt=None, info=info)


def generate_key_version(
    db: Session,
    *,
    algorithm: str = ALG_AES_256_GCM,
    state: str = "PREPARED",
    key_store: KeyMaterialStore | None = None,
) -> KeyMetadata:
    """Create a new versioned key metadata record and isolated secret material."""
    max_version = db.execute(select(func.max(KeyMetadata.version))).scalar_one_or_none() or 0
    next_version = max_version + 1
    now = datetime.now(timezone.utc)

    store = key_store or KeyMaterialStore()
    store.ensure_version_secret(next_version)

    meta = KeyMetadata(
        id=f"key-v{next_version}",
        version=next_version,
        algorithm=algorithm,
        state=state,
        created_at=now,
        activated_at=now if state == "ACTIVE" else None,
    )
    db.add(meta)
    db.commit()
    db.refresh(meta)
    return meta


def list_key_metadata(db: Session) -> list[KeyMetadata]:
    """Return all key metadata records (never exposes secret key material)."""
    return list(db.execute(select(KeyMetadata).order_by(KeyMetadata.version.asc())).scalars().all())


def wrap_dek(
    version: int,
    dek: bytes,
    *,
    resource_id: str,
    key_store: KeyMaterialStore | None = None,
) -> AesGcmSealed:
    """Wrap a per-resource DEK using the HKDF-derived wrapping key for `version`."""
    store = key_store or KeyMaterialStore()
    wrapping_key = store.derive_wrapping_key(version)
    aad = f"qshield:dek-wrap:v{version}:{resource_id}".encode("utf-8")
    return aes_gcm_encrypt(wrapping_key, dek, aad=aad)


def unwrap_dek(
    version: int,
    *,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    resource_id: str,
    key_store: KeyMaterialStore | None = None,
) -> bytes:
    """Unwrap a per-resource DEK using the HKDF-derived wrapping key for `version`."""
    store = key_store or KeyMaterialStore()
    wrapping_key = store.derive_wrapping_key(version)
    aad = f"qshield:dek-wrap:v{version}:{resource_id}".encode("utf-8")
    return aes_gcm_decrypt(wrapping_key, nonce=nonce, ciphertext=ciphertext, tag=tag, aad=aad)


def get_active_key_metadata(db: Session) -> KeyMetadata:
    """Return the current active key metadata (ACTIVE_NEW or ACTIVE)."""
    stmt = (
        select(KeyMetadata)
        .where(KeyMetadata.state.in_(["ACTIVE_NEW", "ACTIVE"]))
        .order_by(KeyMetadata.version.desc())
        .limit(1)
    )
    meta = db.execute(stmt).scalar_one_or_none()
    if meta is None:
        raise CryptoError("No active key metadata available")
    return meta


def rotate_active_key(
    db: Session,
    *,
    operator_actor_id: str,
    reason: str,
    retire_policy: str = "RETIRED",
    key_store: KeyMaterialStore | None = None,
) -> tuple[RotationOperation, KeyMetadata, KeyMetadata, dict[str, object]]:
    """
    Execute the 4-phase key rotation state machine:
    1. PREPARE: generate new key metadata (PREPARED) and isolated secret material.
    2. DISTRIBUTE: mark old key ROTATING, stage new key on simulated nodes.
       If any node is partitioned (NOT_CONVERGED), abort commit safely without corrupting data.
    3. COMMIT: atomically promote new key to ACTIVE_NEW.
    4. RETIRE: transition previous key to RETIRED or REVOKED (zero-grace cutoff for new requests).
    """
    from backend.app.devices.service import _require_operator
    from backend.app.nodes.service import stage_key_version_on_nodes
    from backend.app.services.foundation_service import DomainValidationError, record_audit_event

    _require_operator(db, operator_actor_id)
    if retire_policy not in {"RETIRED", "REVOKED"}:
        raise DomainValidationError("retire_policy must be RETIRED or REVOKED")

    current_key = get_active_key_metadata(db)
    if current_key.state in {"REVOKED", "COMPROMISED"}:
        raise DomainValidationError("Cannot rotate from a REVOKED or COMPROMISED key without recovery")

    # Phase 1: PREPARE
    new_key = generate_key_version(db, algorithm=current_key.algorithm, state="PREPARED", key_store=key_store)
    op = RotationOperation(
        previous_version=current_key.version,
        proposed_version=new_key.version,
        phase="PREPARE",
        committed=False,
        retire_policy=retire_policy,
        actor_id=operator_actor_id,
        reason=reason,
    )
    db.add(op)
    db.commit()
    db.refresh(op)

    # Phase 2: DISTRIBUTE
    current_key.state = "ROTATING"
    op.phase = "DISTRIBUTE"
    db.commit()

    node_result = stage_key_version_on_nodes(
        db, key_version=new_key.version, operation_id=op.operation_id
    )
    if node_result["status"] != "CONVERGED":
        # Safe rollback before commit: restore current_key to ACTIVE, retire prepared key
        current_key.state = "ACTIVE"
        new_key.state = "RETIRED"
        op.phase = "ABORTED_NOT_CONVERGED"
        db.commit()
        record_audit_event(
            db,
            actor_id=operator_actor_id,
            action="key:rotate",
            target=f"v{current_key.version}->v{new_key.version}",
            decision="ABORTED",
            reason="NODE_PARTITION_NOT_CONVERGED",
            correlation_id=op.operation_id,
        )
        raise DomainValidationError("Key rotation aborted: one or more simulated nodes NOT CONVERGED")

    # Phase 3: COMMIT
    now = datetime.now(timezone.utc)
    new_key.state = "ACTIVE_NEW"
    new_key.activated_at = now
    op.phase = "COMMIT"
    op.committed = True
    op.committed_at = now
    db.commit()

    # Phase 4: RETIRE
    current_key.state = retire_policy
    current_key.retired_at = now
    if retire_policy == "REVOKED":
        db.add(
            RevocationTombstone(
                subject_type="key",
                subject_id=current_key.id,
                epoch=new_key.version,
                reason=f"Rotated with REVOKED policy: {reason}",
            )
        )
    op.phase = "RETIRE"
    op.completed_at = now
    db.commit()
    db.refresh(op)
    db.refresh(new_key)
    db.refresh(current_key)

    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="key:rotate",
        target=f"v{current_key.version}->v{new_key.version}",
        decision="COMMITTED",
        reason=reason,
        correlation_id=op.operation_id,
        metadata={"retire_policy": retire_policy, "new_version": new_key.version},
    )
    return op, current_key, new_key, node_result


def mark_key_compromised(
    db: Session,
    *,
    key_id: str,
    operator_actor_id: str,
    reason: str,
    correlation_id: str = "key-compromise",
) -> tuple[KeyMetadata, dict[str, object]]:
    """Transition a key to terminal COMPROMISED state and propagate tombstone to nodes."""
    from backend.app.devices.service import _require_operator
    from backend.app.nodes.service import propagate_revocation_to_nodes
    from backend.app.services.foundation_service import DomainNotFoundError, record_audit_event

    _require_operator(db, operator_actor_id)
    key_meta = db.get(KeyMetadata, key_id)
    if key_meta is None:
        raise DomainNotFoundError(f"Key '{key_id}' not found")

    now = datetime.now(timezone.utc)
    key_meta.state = "COMPROMISED"
    key_meta.compromised_at = now
    tombstone = RevocationTombstone(
        subject_type="key",
        subject_id=key_meta.id,
        epoch=key_meta.version,
        reason=reason,
    )
    db.add(tombstone)
    db.commit()
    db.refresh(key_meta)

    node_result = propagate_revocation_to_nodes(
        db, subject_type="key", subject_id=key_meta.id, epoch=key_meta.version
    )
    record_audit_event(
        db,
        actor_id=operator_actor_id,
        action="key:compromised",
        target=key_meta.id,
        decision="REVOKED",
        reason=reason,
        correlation_id=correlation_id,
    )
    return key_meta, node_result

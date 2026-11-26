"""Encrypted protected-resource vault integrated with 9-step zero-trust authorization."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.crypto.provider import (
    AES_256_KEY_BYTES,
    ALG_AES_256_GCM,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    random_bytes,
)
from backend.app.db.models import KeyMetadata, Resource, VaultEntry
from backend.app.keys.service import KeyMaterialStore, get_active_key_metadata, unwrap_dek, wrap_dek
from backend.app.policy.authz import AuthzDecision, AuthzRequest, evaluate_authorization
from backend.app.services.foundation_service import (
    DomainConflictError,
    DomainNotFoundError,
    DomainValidationError,
    ensure_foundation_defaults,
    record_audit_event,
)

VAULT_SCHEMA_VERSION = "v1"


@dataclass(frozen=True)
class VaultReadResult:
    """Result of an authorized vault read."""

    decision: AuthzDecision
    plaintext: str | None = None
    resource_id: str | None = None
    key_version: int | None = None
    algorithm: str | None = None


def _build_aad(
    *,
    schema_version: str,
    resource_id: str,
    owner_actor_id: str,
    key_version: int,
    algorithm: str,
) -> bytes:
    payload = {
        "schema_version": schema_version,
        "resource_id": resource_id,
        "owner_actor_id": owner_actor_id,
        "key_version": key_version,
        "algorithm": algorithm,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def store_vault_resource(
    db: Session,
    *,
    resource_id: str,
    owner_actor_id: str,
    plaintext: str,
    key_version: int | None = None,
    correlation_id: str = "vault-store",
    key_store: KeyMaterialStore | None = None,
) -> VaultEntry:
    """
    Encrypt `plaintext` with a random per-resource 256-bit DEK (AES-256-GCM)
    and persist only ciphertext, nonce, tag, wrapped DEK, and metadata.
    """
    ensure_foundation_defaults(db)
    if db.get(Resource, resource_id) is not None or db.get(VaultEntry, resource_id) is not None:
        raise DomainConflictError(f"Vault resource '{resource_id}' already exists")

    if key_version is None:
        key_version = get_active_key_metadata(db).version

    key_meta = db.execute(
        select(KeyMetadata).where(KeyMetadata.version == key_version)
    ).scalar_one_or_none()
    if key_meta is None or key_meta.state not in {"ACTIVE", "ACTIVE_NEW"}:
        raise DomainValidationError(f"Key version {key_version} is not active")

    aad = _build_aad(
        schema_version=VAULT_SCHEMA_VERSION,
        resource_id=resource_id,
        owner_actor_id=owner_actor_id,
        key_version=key_version,
        algorithm=ALG_AES_256_GCM,
    )
    dek = random_bytes(AES_256_KEY_BYTES)
    sealed_body = aes_gcm_encrypt(dek, plaintext.encode("utf-8"), aad=aad)
    wrapped = wrap_dek(key_version, dek, resource_id=resource_id, key_store=key_store)
    del dek

    resource = Resource(
        id=resource_id,
        owner_actor_id=owner_actor_id,
        content_ref=f"vault://{resource_id}",
        key_version=key_version,
        state="ACTIVE",
    )
    entry = VaultEntry(
        resource_id=resource_id,
        schema_version=VAULT_SCHEMA_VERSION,
        algorithm=ALG_AES_256_GCM,
        key_version=key_version,
        nonce_b64=base64.b64encode(sealed_body.nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(sealed_body.ciphertext).decode("ascii"),
        tag_b64=base64.b64encode(sealed_body.tag).decode("ascii"),
        wrapped_dek_b64=base64.b64encode(wrapped.ciphertext).decode("ascii"),
        wrapped_dek_nonce_b64=base64.b64encode(wrapped.nonce).decode("ascii"),
        wrapped_dek_tag_b64=base64.b64encode(wrapped.tag).decode("ascii"),
        aad_b64=base64.b64encode(aad).decode("ascii"),
    )
    db.add(resource)
    db.add(entry)
    db.commit()
    db.refresh(entry)

    record_audit_event(
        db,
        actor_id=owner_actor_id,
        action="vault:store",
        target=resource_id,
        decision="ALLOW",
        reason="ENCRYPTED_STORED",
        correlation_id=correlation_id,
        metadata={"key_version": key_version, "algorithm": ALG_AES_256_GCM},
    )
    return entry


def read_vault_resource(
    db: Session,
    authz_req: AuthzRequest,
    *,
    key_store: KeyMaterialStore | None = None,
) -> VaultReadResult:
    """
    Authorize via the 9-step zero-trust pipeline FIRST.
    Only decrypt and return plaintext if decision == 'ALLOW'.
    """
    decision = evaluate_authorization(db, authz_req)
    record_audit_event(
        db,
        actor_id=authz_req.actor_id,
        action="vault:read",
        target=authz_req.resource_id,
        decision=decision.decision,
        reason=decision.reason_code,
        correlation_id=decision.correlation_id,
    )
    if decision.decision != "ALLOW":
        return VaultReadResult(decision=decision)

    entry = db.get(VaultEntry, authz_req.resource_id)
    if entry is None:
        raise DomainNotFoundError(f"Vault entry '{authz_req.resource_id}' not found")

    dek = unwrap_dek(
        entry.key_version,
        nonce=base64.b64decode(entry.wrapped_dek_nonce_b64, validate=True),
        ciphertext=base64.b64decode(entry.wrapped_dek_b64, validate=True),
        tag=base64.b64decode(entry.wrapped_dek_tag_b64, validate=True),
        resource_id=entry.resource_id,
        key_store=key_store,
    )
    try:
        plaintext_bytes = aes_gcm_decrypt(
            dek,
            nonce=base64.b64decode(entry.nonce_b64, validate=True),
            ciphertext=base64.b64decode(entry.ciphertext_b64, validate=True),
            tag=base64.b64decode(entry.tag_b64, validate=True),
            aad=base64.b64decode(entry.aad_b64, validate=True),
        )
    finally:
        del dek

    return VaultReadResult(
        decision=decision,
        plaintext=plaintext_bytes.decode("utf-8"),
        resource_id=entry.resource_id,
        key_version=entry.key_version,
        algorithm=entry.algorithm,
    )

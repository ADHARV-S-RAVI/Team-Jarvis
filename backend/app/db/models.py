"""Foundational SQLAlchemy 2 ORM models for Q-SHIELD Stage 2."""

from __future__ import annotations

from datetime import datetime, timezone
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def new_uuid() -> str:
    """Return an opaque UUID4 string."""
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class Actor(Base):
    """Synthetic identity / user account."""

    __tablename__ = "actors"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    display_label: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    password_hash: Mapped[str | None] = mapped_column(String(256), nullable=True, default=None)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    devices: Mapped[list[Device]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    sessions: Mapped[list[AuthSession]] = relationship(back_populates="actor", cascade="all, delete-orphan")
    resources: Mapped[list[Resource]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class RolePermission(Base):
    """Role-to-permission mapping for server-side RBAC."""

    __tablename__ = "role_permissions"
    __table_args__ = (UniqueConstraint("role", "permission", name="uq_role_permission"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    permission: Mapped[str] = mapped_column(String(64), nullable=False)


class Device(Base):
    """Synthetic device enrolled to an actor."""

    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_actor_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("actors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    credential_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="TRUSTED", index=True)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)

    owner: Mapped[Actor] = relationship(back_populates="devices")
    sessions: Mapped[list[AuthSession]] = relationship(back_populates="device", cascade="all, delete-orphan")


class AuthSession(Base):
    """Opaque actor/device/peer-bound authentication session."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    actor_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("actors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    peer_id: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    actor: Mapped[Actor] = relationship(back_populates="sessions")
    device: Mapped[Device] = relationship(back_populates="sessions")


class KeyMetadata(Base):
    """Minimal key metadata record for authorization key-version verification."""

    __tablename__ = "key_metadata"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    compromised_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Resource(Base):
    """Protected synthetic asset / resource owned by an actor."""

    __tablename__ = "resources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_actor_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("actors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    content_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    state: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    owner: Mapped[Actor] = relationship(back_populates="resources")


class RevocationTombstone(Base):
    """Durable revocation record for actors, devices, sessions, or keys."""

    __tablename__ = "revocation_tombstones"
    __table_args__ = (
        Index("ix_tombstone_subject", "subject_type", "subject_id"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(64), nullable=False)
    epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class IncidentPolicyDenial(Base):
    """Active incident/policy deny rule evaluated in Step 9 of authorization."""

    __tablename__ = "incident_policy_denials"
    __table_args__ = (
        Index("ix_policy_denial_subject", "subject_type", "subject_id", "active"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(64), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class AuditEvent(Base):
    """Foundational structured audit event record."""

    __tablename__ = "audit_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="GENESIS")
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class VaultEntry(Base):
    """Encrypted protected-resource payload; never stores plaintext."""

    __tablename__ = "vault_entries"

    resource_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("resources.id", ondelete="CASCADE"), primary_key=True
    )
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v1")
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="AES-256-GCM")
    key_version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_b64: Mapped[str] = mapped_column(Text, nullable=False)
    tag_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    wrapped_dek_b64: Mapped[str] = mapped_column(Text, nullable=False)
    wrapped_dek_nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    wrapped_dek_tag_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_b64: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class Incident(Base):
    """Security incident record (e.g., lost device, key compromise)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    incident_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="HIGH")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="OPEN", index=True)
    initiator_actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_subject_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentReceipt(Base):
    """Proof-carrying receipt linking an incident to policy, state, nodes, and audit."""

    __tablename__ = "incident_receipts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    incident_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_decision: Mapped[str] = mapped_column(String(64), nullable=False)
    state_transition: Mapped[str] = mapped_column(String(128), nullable=False)
    node_acks_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    convergence_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verification: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_ref: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class SimulatedNode(Base):
    """Deterministic simulated node for local revocation/key propagation."""

    __tablename__ = "simulated_nodes"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    service_name: Mapped[str] = mapped_column(String(64), nullable=False)
    accepted_key_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    revoked_state_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    last_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    health: Mapped[str] = mapped_column(String(24), nullable=False, default="HEALTHY", index=True)
    delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    last_ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enforced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fault_state: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")


class NodeAcknowledgement(Base):
    """Per-node acknowledgement and enforcement timing record."""

    __tablename__ = "node_acknowledgements"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    operation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("simulated_nodes.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enforced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delay_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result: Mapped[str] = mapped_column(String(32), nullable=False, index=True)


class RotationOperation(Base):
    """Key rotation operation tracking PREPARE -> DISTRIBUTE -> COMMIT -> RETIRE."""

    __tablename__ = "rotation_operations"

    operation_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    previous_version: Mapped[int] = mapped_column(Integer, nullable=False)
    proposed_version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    committed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retire_policy: Mapped[str] = mapped_column(String(24), nullable=False, default="RETIRED")
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RotationJournal(Base):
    """Durable integrity-protected journal for crash-safe key rotation recovery."""

    __tablename__ = "rotation_journal"

    operation_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    previous_version: Mapped[int] = mapped_column(Integer, nullable=False)
    proposed_version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    committed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retire_policy: Mapped[str] = mapped_column(String(24), nullable=False, default="RETIRED")
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    committed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_refs_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class BackupManifest(Base):
    """HMAC-authenticated and SHA-256-verified key metadata backup manifest."""

    __tablename__ = "backup_manifests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    backup_epoch: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    active_key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    key_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    manifest_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    hmac_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class DetectorEvent(Base):
    """Ingested security telemetry event with event time, observed time, and clock offset."""

    __tablename__ = "detector_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    adjusted_event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    clock_offset_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    order_uncertain: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    out_of_order: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    actor: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_service: Mapped[str] = mapped_column(String(64), nullable=False)
    target_service: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v1")
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")


class DetectorAlert(Base):
    """Explainable deterministic alert record (rule-based and graph-based, zero ML)."""

    __tablename__ = "detector_alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    score_breakdown_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    path_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    event_refs_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)


class Message(Base):
    """AEAD-encrypted synthetic message with recipient/session/key AAD binding."""

    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    sender_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_b64: Mapped[str] = mapped_column(Text, nullable=False)
    tag_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_b64: Mapped[str] = mapped_column(Text, nullable=False)
    protocol_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="encrypted", index=True)
    failure_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReplayRecord(Base):
    """Durable replay ledger rejecting duplicate message IDs and sequences."""

    __tablename__ = "replay_records"
    __table_args__ = (UniqueConstraint("session_id", "sequence", name="uq_replay_session_seq"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    message_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    recipient_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    result: Mapped[str] = mapped_column(String(32), nullable=False)


class SessionResumptionToken(Base):
    """AEAD-protected, expiry-bound, peer-bound session resumption token record."""

    __tablename__ = "session_resumption_tokens"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    peer_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class UploadSession(Base):
    """Resumable chunked upload session for GB-scale Data Verification Lab."""

    __tablename__ = "upload_sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    declared_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    total_chunks: Mapped[int] = mapped_column(Integer, nullable=False)
    received_chunks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="INITIATED", index=True)
    reference_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    owner_actor_id: Mapped[str] = mapped_column(String(64), nullable=False, default="secop")
    temp_dir: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    chunks: Mapped[list[UploadChunk]] = relationship(back_populates="upload", cascade="all, delete-orphan")


class UploadChunk(Base):
    """Individual verified chunk within a resumable upload session."""

    __tablename__ = "upload_chunks"
    __table_args__ = (UniqueConstraint("upload_id", "chunk_index", name="uq_upload_chunk_idx"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    upload_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("upload_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="VERIFIED")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    upload: Mapped[UploadSession] = relationship(back_populates="chunks")


class VerifiedFile(Base):
    """Reassembled file record with streaming hash, Merkle root, and analysis evidence."""

    __tablename__ = "verified_files"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    upload_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_mime: Mapped[str] = mapped_column(String(128), nullable=False, default="application/octet-stream")
    detected_category: Mapped[str] = mapped_column(String(64), nullable=False, default="binary")
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    merkle_root: Mapped[str | None] = mapped_column(String(64), nullable=True)
    merkle_leaf_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reference_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reference_status: Mapped[str] = mapped_column(String(32), nullable=False, default="REFERENCE_UNAVAILABLE")
    signature_status: Mapped[str] = mapped_column(String(64), nullable=False, default="NONE")
    crypto_readiness: Mapped[str] = mapped_column(String(64), nullable=False, default="Unknown")
    risk_level: Mapped[str] = mapped_column(String(24), nullable=False, default="LOW", index=True)
    verification_status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING", index=True)
    dataset_profile_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    findings_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    receipt_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    stages: Mapped[list[VerificationStage]] = relationship(back_populates="file", cascade="all, delete-orphan")


class VerificationStage(Base):
    """Per-stage execution status and timing for a verified file."""

    __tablename__ = "verification_stages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    file_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("verified_files.id", ondelete="CASCADE"), nullable=False, index=True
    )
    stage_order: Mapped[int] = mapped_column(Integer, nullable=False)
    stage_name: Mapped[str] = mapped_column(String(48), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="Pending")
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False, default="deterministic")
    summary: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    details_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    file: Mapped[VerifiedFile] = relationship(back_populates="stages")


class BackgroundJob(Base):
    """Durable SQLite-backed job queue for 24/7 offline worker execution."""

    __tablename__ = "background_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    job_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="QUEUED", index=True)
    progress_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    checkpoint_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    error_message: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class IdentityCredential(Base):
    """WebAuthn / FIDO2 public-key credential metadata (never stores private keys or biometrics)."""

    __tablename__ = "identity_credentials"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    actor_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("actors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[str | None] = mapped_column(
        String(64), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    credential_id: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    public_key_b64: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    authenticator_metadata: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    credential_status: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class WebAuthnChallenge(Base):
    """Single-use, expiry-bound, actor-bound WebAuthn server challenge."""

    __tablename__ = "webauthn_challenges"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    challenge_b64: Mapped[str] = mapped_column(String(256), nullable=False)
    challenge_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)  # register | authenticate
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class IdentityVerificationEvent(Base):
    """Audit-linked record of identity assurance attempts and freshness windows."""

    __tablename__ = "identity_verification_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    credential_id: Mapped[str | None] = mapped_column(String(512), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_method: Mapped[str] = mapped_column(String(48), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    assurance_level: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class AssurancePolicyConfig(Base):
    """Configurable post-login and sensitive-action verification policy."""

    __tablename__ = "assurance_policy_configs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="default")
    policy_mode: Mapped[str] = mapped_column(String(48), nullable=False, default="OPTIONAL")
    freshness_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    require_user_verification: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    updated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)


class IntegrityManifest(Base):
    """Protected application file integrity baseline manifest."""

    __tablename__ = "integrity_manifests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    manifest_version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_hmac: Mapped[str] = mapped_column(String(64), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="ACTIVE", index=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    entries: Mapped[list[IntegrityManifestEntry]] = relationship(back_populates="manifest", cascade="all, delete-orphan")


class IntegrityManifestEntry(Base):
    """Individual trusted file entry in a baseline manifest."""

    __tablename__ = "integrity_manifest_entries"
    __table_args__ = (UniqueConstraint("manifest_id", "relative_path", name="uq_manifest_rel_path"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    manifest_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("integrity_manifests.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relative_path: Mapped[str] = mapped_column(String(512), nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    file_type: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_status: Mapped[str] = mapped_column(String(24), nullable=False, default="VERIFIED")

    manifest: Mapped[IntegrityManifest] = relationship(back_populates="entries")


class IntegrityScan(Base):
    """Execution record for an application or user-selected integrity scan."""

    __tablename__ = "integrity_scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    manifest_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    scan_scope: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    scan_status: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    files_scanned: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_verified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_modified: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_missing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_unexpected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_unreadable: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    files_excluded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list[IntegrityFinding]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class IntegrityFinding(Base):
    """Per-file finding generated during an integrity scan."""

    __tablename__ = "integrity_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    scan_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("integrity_scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relative_path: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    file_type: Mapped[str] = mapped_column(String(64), nullable=False, default="file")
    file_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    expected_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actual_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    finding_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(24), nullable=False, default="INFO", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    scan: Mapped[IntegrityScan] = relationship(back_populates="findings")


class BaselineChangeRequest(Base):
    """Operator-approved governance workflow for integrity baseline updates."""

    __tablename__ = "baseline_change_requests"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=new_uuid)
    manifest_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    requested_by: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False)
    changes_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    previous_manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    new_manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING", index=True)
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    audit_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

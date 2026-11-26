"""Typed Pydantic v2 request and response schemas for Stage 2 foundation API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    status: Literal["ok"]
    app: str
    version: str
    database: Literal["ok", "error"]


class ErrorResponse(BaseModel):
    error: str
    message: str
    correlation_id: str


class IdentityCreate(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    display_label: str = Field(min_length=1, max_length=128)
    role: Literal["Owner/User", "Security Operator", "Admin", "Auditor", "User", "Employee"]
    enabled: bool = True


class IdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    display_label: str
    role: str
    enabled: bool
    created_at: datetime


class DeviceCreate(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    owner_actor_id: str = Field(min_length=1, max_length=64)
    credential_fingerprint: str = Field(min_length=8, max_length=128)
    state: Literal["PENDING", "TRUSTED", "SUSPENDED", "REVOKED"] = "TRUSTED"


class DeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_actor_id: str
    credential_fingerprint: str
    state: str
    state_version: int
    enrolled_at: datetime
    last_seen_at: datetime | None = None
    revocation_reason: str | None = None


class SessionCreate(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    peer_id: str = Field(min_length=1, max_length=64)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)


class SetPasswordRequest(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=8, max_length=128)
    current_password: str | None = Field(default=None, min_length=1, max_length=128)
    operator_actor_id: str | None = Field(default=None, min_length=1, max_length=64)
    session_id: str | None = Field(default=None, min_length=1, max_length=64)
    session_token: str | None = Field(default=None, min_length=1, max_length=256)


class PasswordLoginRequest(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=64)
    peer_id: str = Field(min_length=1, max_length=64)
    ttl_seconds: int | None = Field(default=None, ge=60, le=86400)


class SessionCreatedResponse(BaseModel):
    id: str
    actor_id: str
    device_id: str
    peer_id: str
    session_token: str
    issued_at: datetime
    expires_at: datetime
    version: int


class SessionValidateRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)
    session_token: str = Field(min_length=1, max_length=256)
    actor_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    peer_id: str | None = Field(default=None, min_length=1, max_length=64)


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    actor_id: str
    device_id: str
    peer_id: str
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    version: int


class ResourceCreate(BaseModel):
    id: str = Field(min_length=1, max_length=64)
    owner_actor_id: str = Field(min_length=1, max_length=64)
    content_ref: str = Field(min_length=1, max_length=256)
    key_version: int = Field(default=1, ge=1)
    state: Literal["ACTIVE", "DISABLED"] = "ACTIVE"


class ResourceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_actor_id: str
    content_ref: str
    key_version: int
    state: str
    created_at: datetime


class PolicyEvaluateRequest(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    resource_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)
    peer_id: str | None = Field(default=None, min_length=1, max_length=64)
    session_token: str | None = Field(default=None, min_length=1, max_length=256)
    in_flight: bool = False


class PolicyEvaluateResponse(BaseModel):
    decision: Literal["ALLOW", "DENY"]
    reason_code: str
    failed_step: int | None
    checks_passed: list[str]
    correlation_id: str


class RevocationCreate(BaseModel):
    subject_type: Literal["actor", "device", "session", "key"]
    subject_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)


class RevocationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    subject_type: str
    subject_id: str
    epoch: int
    reason: str
    created_at: datetime


class RevocationStatusResponse(BaseModel):
    subject_type: str
    subject_id: str
    revoked: bool
    tombstone_count: int
    latest_epoch: int | None = None
    latest_reason: str | None = None


class KeyMetadataResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    version: int
    algorithm: str
    state: str
    created_at: datetime
    activated_at: datetime | None = None
    retired_at: datetime | None = None
    compromised_at: datetime | None = None


class KeyGenerateRequest(BaseModel):
    algorithm: Literal["AES-256-GCM", "ML-KEM-768"] = "AES-256-GCM"
    state: Literal["PREPARED", "ACTIVE"] = "PREPARED"


class VaultStoreRequest(BaseModel):
    resource_id: str = Field(min_length=1, max_length=64)
    owner_actor_id: str = Field(min_length=1, max_length=64)
    plaintext: str = Field(min_length=1, max_length=65536)
    key_version: int | None = Field(default=None, ge=1)


class VaultStoreResponse(BaseModel):
    resource_id: str
    schema_version: str
    algorithm: str
    key_version: int
    created_at: datetime


class VaultReadRequest(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    peer_id: str | None = Field(default=None, min_length=1, max_length=64)
    session_token: str | None = Field(default=None, min_length=1, max_length=256)
    in_flight: bool = False


class VaultReadResponse(BaseModel):
    decision: Literal["ALLOW"]
    resource_id: str
    key_version: int
    algorithm: str
    plaintext: str
    correlation_id: str


class DeviceOperatorActionRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)


class DeviceReplaceRequest(BaseModel):
    owner_actor_id: str = Field(min_length=1, max_length=64)
    new_device_id: str = Field(min_length=1, max_length=64)
    new_credential_fingerprint: str = Field(min_length=8, max_length=128)


class SessionRevokeRequest(BaseModel):
    actor_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(default="User logout / session invalidation", min_length=1, max_length=256)


class LostDeviceReportRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)
    device_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)
    confirmed: bool = False


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_type: str
    severity: str
    status: str
    initiator_actor_id: str
    target_subject_type: str
    target_subject_id: str
    reason: str
    confirmed: bool
    created_at: datetime
    closed_at: datetime | None = None


class IncidentReceiptResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    policy_decision: str
    state_transition: str
    node_acks_json: str
    convergence_ms: int | None = None
    verification: str
    audit_ref: str
    created_at: datetime


class LostDeviceWorkflowResponse(BaseModel):
    incident: IncidentResponse
    receipt: IncidentReceiptResponse
    device: DeviceResponse


class SimulatedNodeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    service_name: str
    accepted_key_version: int
    last_sequence: int
    health: str
    delay_ms: int
    last_ack_at: datetime | None = None
    enforced_at: datetime | None = None
    fault_state: str
    simulated: bool = True


class NodeConfigureRequest(BaseModel):
    count: int = Field(ge=3, le=7)


class NodeLatencyRequest(BaseModel):
    delay_ms: int = Field(ge=0, le=5000)


class KeyRotateRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)
    retire_policy: Literal["RETIRED", "REVOKED"] = "RETIRED"


class KeyRotateResponse(BaseModel):
    operation_id: str
    previous_version: int
    new_version: int
    phase: str
    committed: bool
    retire_policy: str
    node_status: str


class KeyCompromiseRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)


class JournaledRotateRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=256)
    retire_policy: Literal["RETIRED", "REVOKED"] = "RETIRED"
    crash_at: str | None = None


class JournaledRotateResponse(BaseModel):
    operation_id: str
    previous_version: int
    proposed_version: int
    phase: str
    committed: bool
    integrity_hash: str


class RecoverRotationRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)


class BackupCreateRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)


class BackupManifestPayload(BaseModel):
    manifest: dict[str, object]


class BackupRestoreRequest(BaseModel):
    operator_actor_id: str = Field(min_length=1, max_length=64)
    manifest: dict[str, object]


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    sequence: int
    timestamp: datetime
    actor_id: str
    action: str
    target: str
    decision: str
    reason: str
    correlation_id: str
    metadata_json: str
    prev_hash: str
    event_hash: str


class DetectorIngestRequest(BaseModel):
    events: list[dict[str, object]]
    reorder_window_ms: int = Field(default=5000, ge=0, le=60000)
    clock_uncertainty_ms: int = Field(default=500, ge=0, le=10000)


class DetectorRunRequest(BaseModel):
    approvals: list[dict[str, object]] = Field(default_factory=list)


class DetectorAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_id: str
    severity: str
    actor: str
    score_breakdown_json: str
    path_json: str
    event_refs_json: str
    created_at: datetime
    explanation: str


class DetectorMetricsRequest(BaseModel):
    labels: dict[str, str] | None = None
    dataset_version: str = "custom"
    seed: int | None = None


class MessageSendRequest(BaseModel):
    sender_id: str = Field(min_length=1, max_length=64)
    recipient_id: str = Field(min_length=1, max_length=64)
    session_id: str = Field(min_length=1, max_length=64)
    plaintext: str = Field(min_length=1, max_length=65536)
    ttl_seconds: int = Field(default=300, ge=10, le=86400)
    simulate_pending_recovery: bool = False


class MessageResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    sender_id: str
    recipient_id: str
    session_id: str
    sequence: int
    key_version: int
    protocol_version: str
    status: str
    failure_reason: str | None = None
    created_at: datetime
    expires_at: datetime
    delivered_at: datetime | None = None


class MessageDeliverRequest(BaseModel):
    recipient_id: str = Field(min_length=1, max_length=64)
    override_aad_b64: str | None = None


class MessageRecoverRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)
    recipient_id: str = Field(min_length=1, max_length=64)


class ResumptionIssueRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)
    actor_id: str = Field(min_length=1, max_length=64)
    peer_id: str = Field(min_length=1, max_length=64)
    ttl_seconds: int = Field(default=300, ge=10, le=86400)


class ResumptionResumeRequest(BaseModel):
    token_bundle: dict[str, str]
    actor_id: str = Field(min_length=1, max_length=64)
    peer_id: str = Field(min_length=1, max_length=64)

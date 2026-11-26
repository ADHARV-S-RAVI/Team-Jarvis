"""Initial Stage 2 foundation schema.

Revision ID: 0001_initial_foundation
Revises: None
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial_foundation"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "actors",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("display_label", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_actors_role", "actors", ["role"])

    op.create_table(
        "role_permissions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("permission", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("role", "permission", name="uq_role_permission"),
    )
    op.create_index("ix_role_permissions_role", "role_permissions", ["role"])

    op.create_table(
        "devices",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("owner_actor_id", sa.String(length=64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("credential_fingerprint", sa.String(length=128), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=256), nullable=True),
    )
    op.create_index("ix_devices_owner_actor_id", "devices", ["owner_actor_id"])
    op.create_index("ix_devices_state", "devices", ["state"])

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("token_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(length=64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(length=64), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False),
        sa.Column("peer_id", sa.String(length=64), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
    )
    op.create_index("ix_sessions_token_hash", "sessions", ["token_hash"], unique=True)
    op.create_index("ix_sessions_actor_id", "sessions", ["actor_id"])
    op.create_index("ix_sessions_device_id", "sessions", ["device_id"])

    op.create_table(
        "key_metadata",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("version", sa.Integer(), nullable=False, unique=True),
        sa.Column("algorithm", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("compromised_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_key_metadata_version", "key_metadata", ["version"], unique=True)
    op.create_index("ix_key_metadata_state", "key_metadata", ["state"])

    op.create_table(
        "resources",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("owner_actor_id", sa.String(length=64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("content_ref", sa.String(length=256), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_resources_owner_actor_id", "resources", ["owner_actor_id"])
    op.create_index("ix_resources_state", "resources", ["state"])

    op.create_table(
        "revocation_tombstones",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("epoch", sa.Integer(), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tombstone_subject", "revocation_tombstones", ["subject_type", "subject_id"])

    op.create_table(
        "incident_policy_denials",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_denial_subject", "incident_policy_denials", ["subject_type", "subject_id", "active"])

    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(length=64), primary_key=True),
        sa.Column("sequence", sa.Integer(), nullable=False, unique=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target", sa.String(length=128), nullable=False),
        sa.Column("decision", sa.String(length=32), nullable=False),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("prev_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
    )
    op.create_index("ix_audit_events_sequence", "audit_events", ["sequence"], unique=True)
    op.create_index("ix_audit_events_timestamp", "audit_events", ["timestamp"])
    op.create_index("ix_audit_events_actor_id", "audit_events", ["actor_id"])
    op.create_index("ix_audit_events_correlation_id", "audit_events", ["correlation_id"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("incident_policy_denials")
    op.drop_table("revocation_tombstones")
    op.drop_table("resources")
    op.drop_table("key_metadata")
    op.drop_table("sessions")
    op.drop_table("devices")
    op.drop_table("role_permissions")
    op.drop_table("actors")

"""Add Stage 13 Identity Assurance and File Integrity Monitoring tables.

Revision ID: 0009_stage13_identity_and_integrity
Revises: 0008_datalab_and_jobs
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0009_stage13_identity_and_integrity"
down_revision: Union[str, Sequence[str], None] = "0008_datalab_and_jobs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "identity_credentials",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("actor_id", sa.String(length=64), sa.ForeignKey("actors.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(length=64), sa.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True),
        sa.Column("credential_id", sa.String(length=512), nullable=False, unique=True),
        sa.Column("public_key_b64", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("authenticator_metadata", sa.Text(), nullable=False),
        sa.Column("credential_status", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_identity_credentials_actor_id", "identity_credentials", ["actor_id"])
    op.create_index("ix_identity_credentials_credential_id", "identity_credentials", ["credential_id"])
    op.create_index("ix_identity_credentials_credential_status", "identity_credentials", ["credential_status"])

    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("challenge_b64", sa.String(length=256), nullable=False),
        sa.Column("challenge_hash", sa.String(length=64), nullable=False, unique=True),
        sa.Column("purpose", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_webauthn_challenges_actor_id", "webauthn_challenges", ["actor_id"])

    op.create_table(
        "identity_verification_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("credential_id", sa.String(length=512), nullable=True),
        sa.Column("device_id", sa.String(length=64), nullable=True),
        sa.Column("verification_method", sa.String(length=48), nullable=False),
        sa.Column("verification_status", sa.String(length=32), nullable=False),
        sa.Column("assurance_level", sa.String(length=32), nullable=False),
        sa.Column("fresh_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_identity_verification_events_actor_id", "identity_verification_events", ["actor_id"])
    op.create_index("ix_identity_verification_events_status", "identity_verification_events", ["verification_status"])

    op.create_table(
        "assurance_policy_configs",
        sa.Column("id", sa.String(length=32), primary_key=True),
        sa.Column("policy_mode", sa.String(length=48), nullable=False),
        sa.Column("freshness_window_seconds", sa.Integer(), nullable=False),
        sa.Column("require_user_verification", sa.Boolean(), nullable=False),
        sa.Column("updated_by", sa.String(length=64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "integrity_manifests",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("manifest_version", sa.Integer(), nullable=False),
        sa.Column("root_hash", sa.String(length=64), nullable=False),
        sa.Column("manifest_hmac", sa.String(length=64), nullable=False),
        sa.Column("scanner_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("approved_by", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_integrity_manifests_version", "integrity_manifests", ["manifest_version"])
    op.create_index("ix_integrity_manifests_status", "integrity_manifests", ["status"])

    op.create_table(
        "integrity_manifest_entries",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("manifest_id", sa.String(length=64), sa.ForeignKey("integrity_manifests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relative_path", sa.String(length=512), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("file_type", sa.String(length=64), nullable=False),
        sa.Column("baseline_status", sa.String(length=24), nullable=False),
        sa.UniqueConstraint("manifest_id", "relative_path", name="uq_manifest_rel_path"),
    )
    op.create_index("ix_integrity_manifest_entries_manifest_id", "integrity_manifest_entries", ["manifest_id"])

    op.create_table(
        "integrity_scans",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("manifest_id", sa.String(length=64), nullable=True),
        sa.Column("scan_scope", sa.String(length=32), nullable=False),
        sa.Column("scan_status", sa.String(length=24), nullable=False),
        sa.Column("files_scanned", sa.Integer(), nullable=False),
        sa.Column("files_verified", sa.Integer(), nullable=False),
        sa.Column("files_modified", sa.Integer(), nullable=False),
        sa.Column("files_missing", sa.Integer(), nullable=False),
        sa.Column("files_unexpected", sa.Integer(), nullable=False),
        sa.Column("files_unreadable", sa.Integer(), nullable=False),
        sa.Column("files_excluded", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_integrity_scans_scope", "integrity_scans", ["scan_scope"])

    op.create_table(
        "integrity_findings",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("scan_id", sa.String(length=64), sa.ForeignKey("integrity_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relative_path", sa.String(length=512), nullable=False),
        sa.Column("file_type", sa.String(length=64), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=False),
        sa.Column("expected_hash", sa.String(length=64), nullable=True),
        sa.Column("actual_hash", sa.String(length=64), nullable=True),
        sa.Column("finding_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_integrity_findings_scan_id", "integrity_findings", ["scan_id"])

    op.create_table(
        "baseline_change_requests",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("manifest_id", sa.String(length=64), nullable=False),
        sa.Column("requested_by", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("changes_json", sa.Text(), nullable=False),
        sa.Column("previous_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("new_manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("approved_by", sa.String(length=64), nullable=True),
        sa.Column("audit_ref", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_baseline_change_requests_status", "baseline_change_requests", ["status"])


def downgrade() -> None:
    op.drop_table("baseline_change_requests")
    op.drop_table("integrity_findings")
    op.drop_table("integrity_scans")
    op.drop_table("integrity_manifest_entries")
    op.drop_table("integrity_manifests")
    op.drop_table("assurance_policy_configs")
    op.drop_table("identity_verification_events")
    op.drop_table("webauthn_challenges")
    op.drop_table("identity_credentials")

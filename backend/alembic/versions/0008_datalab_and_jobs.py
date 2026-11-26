"""Add Data Verification Lab and durable background job tables.

Revision ID: 0008_datalab_and_jobs
Revises: 0007_messaging_and_replay
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_datalab_and_jobs"
down_revision: Union[str, Sequence[str], None] = "0007_messaging_and_replay"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "upload_sessions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("filename", sa.String(length=256), nullable=False),
        sa.Column("declared_size_bytes", sa.Integer(), nullable=False),
        sa.Column("chunk_size_bytes", sa.Integer(), nullable=False),
        sa.Column("total_chunks", sa.Integer(), nullable=False),
        sa.Column("received_chunks", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("reference_sha256", sa.String(length=64), nullable=True),
        sa.Column("owner_actor_id", sa.String(length=64), nullable=False),
        sa.Column("temp_dir", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_upload_sessions_status", "upload_sessions", ["status"])

    op.create_table(
        "upload_chunks",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("upload_id", sa.String(length=64), sa.ForeignKey("upload_sessions.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("chunk_sha256", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("upload_id", "chunk_index", name="uq_upload_chunk_idx"),
    )
    op.create_index("ix_upload_chunks_upload_id", "upload_chunks", ["upload_id"])

    op.create_table(
        "verified_files",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("upload_id", sa.String(length=64), nullable=False),
        sa.Column("filename", sa.String(length=256), nullable=False),
        sa.Column("storage_path", sa.String(length=512), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("detected_mime", sa.String(length=128), nullable=False),
        sa.Column("detected_category", sa.String(length=64), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("merkle_root", sa.String(length=64), nullable=True),
        sa.Column("merkle_leaf_count", sa.Integer(), nullable=False),
        sa.Column("reference_sha256", sa.String(length=64), nullable=True),
        sa.Column("reference_status", sa.String(length=32), nullable=False),
        sa.Column("signature_status", sa.String(length=64), nullable=False),
        sa.Column("crypto_readiness", sa.String(length=64), nullable=False),
        sa.Column("risk_level", sa.String(length=24), nullable=False),
        sa.Column("verification_status", sa.String(length=24), nullable=False),
        sa.Column("dataset_profile_json", sa.Text(), nullable=True),
        sa.Column("findings_json", sa.Text(), nullable=False),
        sa.Column("receipt_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_verified_files_upload_id", "verified_files", ["upload_id"])
    op.create_index("ix_verified_files_filename", "verified_files", ["filename"])
    op.create_index("ix_verified_files_sha256", "verified_files", ["sha256"])
    op.create_index("ix_verified_files_risk_level", "verified_files", ["risk_level"])
    op.create_index("ix_verified_files_verification_status", "verified_files", ["verification_status"])

    op.create_table(
        "verification_stages",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("file_id", sa.String(length=64), sa.ForeignKey("verified_files.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stage_order", sa.Integer(), nullable=False),
        sa.Column("stage_name", sa.String(length=48), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("algorithm", sa.String(length=64), nullable=False),
        sa.Column("summary", sa.String(length=512), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_verification_stages_file_id", "verification_stages", ["file_id"])

    op.create_table(
        "background_jobs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("job_type", sa.String(length=48), nullable=False),
        sa.Column("target_id", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("progress_pct", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("checkpoint_json", sa.Text(), nullable=False),
        sa.Column("error_message", sa.String(length=512), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_background_jobs_job_type", "background_jobs", ["job_type"])
    op.create_index("ix_background_jobs_target_id", "background_jobs", ["target_id"])
    op.create_index("ix_background_jobs_status", "background_jobs", ["status"])


def downgrade() -> None:
    op.drop_table("background_jobs")
    op.drop_table("verification_stages")
    op.drop_table("verified_files")
    op.drop_table("upload_chunks")
    op.drop_table("upload_sessions")

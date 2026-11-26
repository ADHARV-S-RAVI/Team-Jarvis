"""Add rotation_journal and backup_manifests tables for Stage 6 crash recovery.

Revision ID: 0005_rotation_journal_and_backups
Revises: 0004_nodes_and_key_rotation
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_rotation_journal_and_backups"
down_revision: Union[str, Sequence[str], None] = "0004_nodes_and_key_rotation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "rotation_journal",
        sa.Column("operation_id", sa.String(length=64), primary_key=True),
        sa.Column("previous_version", sa.Integer(), nullable=False),
        sa.Column("proposed_version", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("committed", sa.Boolean(), nullable=False),
        sa.Column("retire_policy", sa.String(length=24), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("integrity_hash", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("recovered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_refs_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_rotation_journal_proposed_version", "rotation_journal", ["proposed_version"])
    op.create_index("ix_rotation_journal_phase", "rotation_journal", ["phase"])

    op.create_table(
        "backup_manifests",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("backup_epoch", sa.Integer(), nullable=False),
        sa.Column("active_key_version", sa.Integer(), nullable=False),
        sa.Column("key_ids_json", sa.Text(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("hmac_hex", sa.String(length=64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_backup_manifests_backup_epoch", "backup_manifests", ["backup_epoch"])


def downgrade() -> None:
    op.drop_index("ix_backup_manifests_backup_epoch", table_name="backup_manifests")
    op.drop_table("backup_manifests")
    op.drop_index("ix_rotation_journal_phase", table_name="rotation_journal")
    op.drop_index("ix_rotation_journal_proposed_version", table_name="rotation_journal")
    op.drop_table("rotation_journal")

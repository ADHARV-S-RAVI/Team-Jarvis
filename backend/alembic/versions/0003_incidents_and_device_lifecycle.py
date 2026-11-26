"""Add incidents and incident_receipts tables for Stage 4 lost-device workflow.

Revision ID: 0003_incidents_and_device_lifecycle
Revises: 0002_vault_entries
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_incidents_and_device_lifecycle"
down_revision: Union[str, Sequence[str], None] = "0002_vault_entries"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("incident_type", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("initiator_actor_id", sa.String(length=64), nullable=False),
        sa.Column("target_subject_type", sa.String(length=32), nullable=False),
        sa.Column("target_subject_id", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_incident_type", "incidents", ["incident_type"])
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_target_subject_id", "incidents", ["target_subject_id"])

    op.create_table(
        "incident_receipts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "incident_id",
            sa.String(length=64),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("policy_decision", sa.String(length=64), nullable=False),
        sa.Column("state_transition", sa.String(length=128), nullable=False),
        sa.Column("node_acks_json", sa.Text(), nullable=False),
        sa.Column("convergence_ms", sa.Integer(), nullable=True),
        sa.Column("verification", sa.String(length=64), nullable=False),
        sa.Column("audit_ref", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_incident_receipts_incident_id", "incident_receipts", ["incident_id"])
    op.create_index("ix_incident_receipts_audit_ref", "incident_receipts", ["audit_ref"])


def downgrade() -> None:
    op.drop_index("ix_incident_receipts_audit_ref", table_name="incident_receipts")
    op.drop_index("ix_incident_receipts_incident_id", table_name="incident_receipts")
    op.drop_table("incident_receipts")
    op.drop_index("ix_incidents_target_subject_id", table_name="incidents")
    op.drop_index("ix_incidents_status", table_name="incidents")
    op.drop_index("ix_incidents_incident_type", table_name="incidents")
    op.drop_table("incidents")

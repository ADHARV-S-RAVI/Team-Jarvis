"""Add detector_events and detector_alerts tables for Stage 8 deterministic detection.

Revision ID: 0006_detector_events_and_alerts
Revises: 0005_rotation_journal_and_backups
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_detector_events_and_alerts"
down_revision: Union[str, Sequence[str], None] = "0005_rotation_journal_and_backups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detector_events",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("adjusted_event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("clock_offset_ms", sa.Integer(), nullable=False),
        sa.Column("order_uncertain", sa.Boolean(), nullable=False),
        sa.Column("out_of_order", sa.Boolean(), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("source_service", sa.String(length=64), nullable=False),
        sa.Column("target_service", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
    )
    op.create_index("ix_detector_events_event_time", "detector_events", ["event_time"])
    op.create_index("ix_detector_events_adjusted_event_time", "detector_events", ["adjusted_event_time"])
    op.create_index("ix_detector_events_actor", "detector_events", ["actor"])
    op.create_index("ix_detector_events_session_id", "detector_events", ["session_id"])
    op.create_index("ix_detector_events_correlation_id", "detector_events", ["correlation_id"])

    op.create_table(
        "detector_alerts",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("rule_id", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("score_breakdown_json", sa.Text(), nullable=False),
        sa.Column("path_json", sa.Text(), nullable=False),
        sa.Column("event_refs_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
    )
    op.create_index("ix_detector_alerts_rule_id", "detector_alerts", ["rule_id"])
    op.create_index("ix_detector_alerts_severity", "detector_alerts", ["severity"])
    op.create_index("ix_detector_alerts_actor", "detector_alerts", ["actor"])


def downgrade() -> None:
    op.drop_index("ix_detector_alerts_actor", table_name="detector_alerts")
    op.drop_index("ix_detector_alerts_severity", table_name="detector_alerts")
    op.drop_index("ix_detector_alerts_rule_id", table_name="detector_alerts")
    op.drop_table("detector_alerts")
    op.drop_index("ix_detector_events_correlation_id", table_name="detector_events")
    op.drop_index("ix_detector_events_session_id", table_name="detector_events")
    op.drop_index("ix_detector_events_actor", table_name="detector_events")
    op.drop_index("ix_detector_events_adjusted_event_time", table_name="detector_events")
    op.drop_index("ix_detector_events_event_time", table_name="detector_events")
    op.drop_table("detector_events")

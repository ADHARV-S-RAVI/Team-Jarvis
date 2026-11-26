"""Add simulated_nodes, node_acknowledgements, and rotation_operations tables.

Revision ID: 0004_nodes_and_key_rotation
Revises: 0003_incidents_and_device_lifecycle
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_nodes_and_key_rotation"
down_revision: Union[str, Sequence[str], None] = "0003_incidents_and_device_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "simulated_nodes",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("service_name", sa.String(length=64), nullable=False),
        sa.Column("accepted_key_version", sa.Integer(), nullable=False),
        sa.Column("revoked_state_json", sa.Text(), nullable=False),
        sa.Column("last_sequence", sa.Integer(), nullable=False),
        sa.Column("health", sa.String(length=24), nullable=False),
        sa.Column("delay_ms", sa.Integer(), nullable=False),
        sa.Column("last_ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enforced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fault_state", sa.String(length=32), nullable=False),
    )
    op.create_index("ix_simulated_nodes_health", "simulated_nodes", ["health"])

    op.create_table(
        "node_acknowledgements",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("operation_id", sa.String(length=64), nullable=False),
        sa.Column(
            "node_id",
            sa.String(length=64),
            sa.ForeignKey("simulated_nodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("ack_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("enforced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delay_ms", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
    )
    op.create_index("ix_node_acknowledgements_operation_id", "node_acknowledgements", ["operation_id"])
    op.create_index("ix_node_acknowledgements_node_id", "node_acknowledgements", ["node_id"])
    op.create_index("ix_node_acknowledgements_result", "node_acknowledgements", ["result"])

    op.create_table(
        "rotation_operations",
        sa.Column("operation_id", sa.String(length=64), primary_key=True),
        sa.Column("previous_version", sa.Integer(), nullable=False),
        sa.Column("proposed_version", sa.Integer(), nullable=False),
        sa.Column("phase", sa.String(length=24), nullable=False),
        sa.Column("committed", sa.Boolean(), nullable=False),
        sa.Column("retire_policy", sa.String(length=24), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=256), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_rotation_operations_proposed_version", "rotation_operations", ["proposed_version"])
    op.create_index("ix_rotation_operations_phase", "rotation_operations", ["phase"])


def downgrade() -> None:
    op.drop_index("ix_rotation_operations_phase", table_name="rotation_operations")
    op.drop_index("ix_rotation_operations_proposed_version", table_name="rotation_operations")
    op.drop_table("rotation_operations")
    op.drop_index("ix_node_acknowledgements_result", table_name="node_acknowledgements")
    op.drop_index("ix_node_acknowledgements_node_id", table_name="node_acknowledgements")
    op.drop_index("ix_node_acknowledgements_operation_id", table_name="node_acknowledgements")
    op.drop_table("node_acknowledgements")
    op.drop_index("ix_simulated_nodes_health", table_name="simulated_nodes")
    op.drop_table("simulated_nodes")

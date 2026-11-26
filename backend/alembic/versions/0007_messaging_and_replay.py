"""Add messages, replay_records, and session_resumption_tokens tables for Stage 9.

Revision ID: 0007_messaging_and_replay
Revises: 0006_detector_events_and_alerts
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_messaging_and_replay"
down_revision: Union[str, Sequence[str], None] = "0006_detector_events_and_alerts"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "messages",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("sender_id", sa.String(length=64), nullable=False),
        sa.Column("recipient_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("nonce_b64", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_b64", sa.Text(), nullable=False),
        sa.Column("tag_b64", sa.String(length=64), nullable=False),
        sa.Column("aad_b64", sa.Text(), nullable=False),
        sa.Column("protocol_version", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failure_reason", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_messages_sender_id", "messages", ["sender_id"])
    op.create_index("ix_messages_recipient_id", "messages", ["recipient_id"])
    op.create_index("ix_messages_session_id", "messages", ["session_id"])
    op.create_index("ix_messages_status", "messages", ["status"])

    op.create_table(
        "replay_records",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("message_id", sa.String(length=64), nullable=False, unique=True),
        sa.Column("recipient_id", sa.String(length=64), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.UniqueConstraint("session_id", "sequence", name="uq_replay_session_seq"),
    )
    op.create_index("ix_replay_records_message_id", "replay_records", ["message_id"], unique=True)
    op.create_index("ix_replay_records_recipient_id", "replay_records", ["recipient_id"])

    op.create_table(
        "session_resumption_tokens",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("actor_id", sa.String(length=64), nullable=False),
        sa.Column("peer_id", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_session_resumption_tokens_session_id", "session_resumption_tokens", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_session_resumption_tokens_session_id", table_name="session_resumption_tokens")
    op.drop_table("session_resumption_tokens")
    op.drop_index("ix_replay_records_recipient_id", table_name="replay_records")
    op.drop_index("ix_replay_records_message_id", table_name="replay_records")
    op.drop_table("replay_records")
    op.drop_index("ix_messages_status", table_name="messages")
    op.drop_index("ix_messages_session_id", table_name="messages")
    op.drop_index("ix_messages_recipient_id", table_name="messages")
    op.drop_index("ix_messages_sender_id", table_name="messages")
    op.drop_table("messages")

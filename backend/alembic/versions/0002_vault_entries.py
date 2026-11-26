"""Add vault_entries table for encrypted protected resources.

Revision ID: 0002_vault_entries
Revises: 0001_initial_foundation
Create Date: 2026-11-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_vault_entries"
down_revision: Union[str, Sequence[str], None] = "0001_initial_foundation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "vault_entries",
        sa.Column(
            "resource_id",
            sa.String(length=64),
            sa.ForeignKey("resources.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("key_version", sa.Integer(), nullable=False),
        sa.Column("nonce_b64", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_b64", sa.Text(), nullable=False),
        sa.Column("tag_b64", sa.String(length=64), nullable=False),
        sa.Column("wrapped_dek_b64", sa.Text(), nullable=False),
        sa.Column("wrapped_dek_nonce_b64", sa.String(length=64), nullable=False),
        sa.Column("wrapped_dek_tag_b64", sa.String(length=64), nullable=False),
        sa.Column("aad_b64", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vault_entries_key_version", "vault_entries", ["key_version"])


def downgrade() -> None:
    op.drop_index("ix_vault_entries_key_version", table_name="vault_entries")
    op.drop_table("vault_entries")

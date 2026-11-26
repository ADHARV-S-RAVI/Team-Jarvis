"""Add optional salted password_hash column to actors table.

Revision ID: 0010_actor_password_hash
Revises: 0009_stage13_identity_and_integrity
Create Date: 2026-11-26
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0010_actor_password_hash"
down_revision = "0009_stage13_identity_and_integrity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("actors", sa.Column("password_hash", sa.String(length=256), nullable=True))


def downgrade() -> None:
    op.drop_column("actors", "password_hash")

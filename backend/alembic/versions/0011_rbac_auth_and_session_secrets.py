"""Add RBAC email, lockout, session secret hash, verification state, and protected_files table.

Revision ID: 0011_rbac_auth_and_session_secrets
Revises: 0010_actor_password_hash
Create Date: 2026-11-27
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0011_rbac_auth_and_session_secrets"
down_revision = "0010_actor_password_hash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("actors", sa.Column("email", sa.String(length=128), nullable=True))
    op.add_column("actors", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_actors_email", "actors", ["email"], unique=True)

    op.add_column("sessions", sa.Column("session_secret_hash", sa.String(length=128), nullable=True))
    op.add_column("sessions", sa.Column("identity_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("sessions", sa.Column("verification_method", sa.String(length=32), nullable=True))

    op.create_table(
        "protected_files",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("required_role", sa.String(length=32), nullable=False),
        sa.Column("assigned_actor_id", sa.String(length=64), sa.ForeignKey("actors.id", ondelete="SET NULL"), nullable=True),
        sa.Column("content_text", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_protected_files_required_role", "protected_files", ["required_role"], unique=False)
    op.create_index("ix_protected_files_assigned_actor_id", "protected_files", ["assigned_actor_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_protected_files_assigned_actor_id", table_name="protected_files")
    op.drop_index("ix_protected_files_required_role", table_name="protected_files")
    op.drop_table("protected_files")

    op.drop_column("sessions", "verification_method")
    op.drop_column("sessions", "identity_verified_at")
    op.drop_column("sessions", "session_secret_hash")

    op.drop_index("ix_actors_email", table_name="actors")
    op.drop_column("actors", "locked_until")
    op.drop_column("actors", "email")

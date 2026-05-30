"""Add encrypted per-user display names on user_files.

Revision ID: 20260318_0002
Revises: 20260311_0001
Create Date: 2026-03-18 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260318_0002"
down_revision = "20260311_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user_files", sa.Column("enc_display_name_b64", sa.Text(), nullable=True))
    op.add_column("user_files", sa.Column("display_name_nonce_b64", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("user_files", "display_name_nonce_b64")
    op.drop_column("user_files", "enc_display_name_b64")

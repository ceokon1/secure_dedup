"""initial schema

Revision ID: 20260311_0001
Revises: 
Create Date: 2026-03-11 00:00:00
"""

from alembic import op
import sqlalchemy as sa

revision = "20260311_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("enc_urk_b64", sa.Text(), nullable=False),
        sa.Column("enc_urk_nonce_b64", sa.Text(), nullable=False),
        sa.Column("kek_salt_b64", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "files",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("tag_hex", sa.String(length=64), nullable=False),
        sa.Column("pk_pow_b64", sa.Text(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("manifest_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_files_tag_hex", "files", ["tag_hex"], unique=True)
    op.create_index("uq_files_object_key", "files", ["object_key"], unique=True)

    op.create_table(
        "user_files",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("file_id", sa.String(length=36), nullable=False),
        sa.Column("wrapped_kf_b64", sa.Text(), nullable=False),
        sa.Column("wk_nonce_b64", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["file_id"], ["files.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", "file_id", name="uq_user_file_user_id_file_id"),
    )
    op.create_index("ix_user_files_user_id", "user_files", ["user_id"], unique=False)
    op.create_index("ix_user_files_file_id", "user_files", ["file_id"], unique=False)

    op.create_table(
        "pow_challenges",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("tag_hex", sa.String(length=64), nullable=False),
        sa.Column("nonce_b64", sa.Text(), nullable=False),
        sa.Column("context", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_pow_challenges_user_id", "pow_challenges", ["user_id"], unique=False)
    op.create_index("ix_pow_challenges_tag_hex", "pow_challenges", ["tag_hex"], unique=False)

    op.create_table(
        "upload_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("tag_hex", sa.String(length=64), nullable=False),
        sa.Column("pk_pow_b64", sa.Text(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.Column("manifest_json", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_upload_sessions_user_id", "upload_sessions", ["user_id"], unique=False)
    op.create_index("ix_upload_sessions_tag_hex", "upload_sessions", ["tag_hex"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_upload_sessions_tag_hex", table_name="upload_sessions")
    op.drop_index("ix_upload_sessions_user_id", table_name="upload_sessions")
    op.drop_table("upload_sessions")

    op.drop_index("ix_pow_challenges_tag_hex", table_name="pow_challenges")
    op.drop_index("ix_pow_challenges_user_id", table_name="pow_challenges")
    op.drop_table("pow_challenges")

    op.drop_index("ix_user_files_file_id", table_name="user_files")
    op.drop_index("ix_user_files_user_id", table_name="user_files")
    op.drop_table("user_files")

    op.drop_index("uq_files_object_key", table_name="files")
    op.drop_index("ix_files_tag_hex", table_name="files")
    op.drop_table("files")

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")

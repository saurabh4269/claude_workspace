"""Add profile_result column to scans table.

Revision ID: 5b7c3d2e0f8a
Revises: 4a8b2c1d9e7f
Create Date: 2026-04-23
"""

from alembic import op
import sqlalchemy as sa

revision = "5b7c3d2e0f8a"
down_revision = "4a8b2c1d9e7f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(sa.Column("profile_result", sa.Text, nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch_op:
        batch_op.drop_column("profile_result")

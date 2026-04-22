"""Add quality scoring, compliance, KEV cache, FTS, policy columns.

Revision ID: 4a8b2c1d9e7f
Revises: 3f6156dd8771
Create Date: 2026-04-21
"""

from alembic import op
import sqlalchemy as sa

revision = "4a8b2c1d9e7f"
down_revision = "3f6156dd8771"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # -----------------------------------------------------------------------
    # Scan table: quality score + compliance + dependency graph columns
    # -----------------------------------------------------------------------
    with op.batch_alter_table("scans") as batch_op:
        batch_op.add_column(sa.Column("quality_score", sa.Float, nullable=True))
        batch_op.add_column(sa.Column("quality_grade", sa.String(2), nullable=True))
        batch_op.add_column(sa.Column("category_scores", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("dependency_graph", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("ntia_result", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("bsi_result", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("fsct_result", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("oct_result", sa.Text, nullable=True))
        batch_op.add_column(sa.Column("policy_result", sa.Text, nullable=True))

    # -----------------------------------------------------------------------
    # KEV cache table
    # -----------------------------------------------------------------------
    op.create_table(
        "kev_cache",
        sa.Column("cve_id", sa.String(50), primary_key=True),
        sa.Column("vendor_project", sa.String(255), nullable=True),
        sa.Column("product", sa.String(255), nullable=True),
        sa.Column("vulnerability_name", sa.String(500), nullable=True),
        sa.Column("due_date", sa.String(50), nullable=True),
        sa.Column("fetched_at", sa.DateTime, nullable=True),
    )

    # -----------------------------------------------------------------------
    # Workspace policy table
    # -----------------------------------------------------------------------
    op.create_table(
        "workspace_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(36),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("name", sa.String(255), nullable=False, default="Default Policy"),
        sa.Column("policy_yaml", sa.Text, nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime,
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # -----------------------------------------------------------------------
    # SQLite FTS5 virtual table for component full-text search
    # -----------------------------------------------------------------------
    op.execute(
        """
        CREATE VIRTUAL TABLE IF NOT EXISTS component_fts
        USING fts5(
            component_id UNINDEXED,
            scan_id UNINDEXED,
            name,
            version,
            purl,
            content='scan_components',
            content_rowid='rowid'
        )
        """
    )

    # Populate FTS from existing data
    op.execute(
        """
        INSERT INTO component_fts(rowid, component_id, scan_id, name, version, purl)
        SELECT rowid, id, scan_id, name,
               COALESCE(version, ''),
               COALESCE(purl, '')
        FROM scan_components
        """
    )

    # Triggers to keep FTS in sync
    op.execute(
        """
        CREATE TRIGGER IF NOT EXISTS component_fts_ai
        AFTER INSERT ON scan_components BEGIN
            INSERT INTO component_fts(rowid, component_id, scan_id, name, version, purl)
            VALUES (new.rowid, new.id, new.scan_id, new.name,
                    COALESCE(new.version, ''), COALESCE(new.purl, ''));
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER IF NOT EXISTS component_fts_ad
        AFTER DELETE ON scan_components BEGIN
            INSERT INTO component_fts(component_fts, rowid, component_id, scan_id, name, version, purl)
            VALUES ('delete', old.rowid, old.id, old.scan_id, old.name,
                    COALESCE(old.version, ''), COALESCE(old.purl, ''));
        END
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS component_fts_ad")
    op.execute("DROP TRIGGER IF EXISTS component_fts_ai")
    op.execute("DROP TABLE IF EXISTS component_fts")
    op.drop_table("workspace_policies")
    op.drop_table("kev_cache")
    with op.batch_alter_table("scans") as batch_op:
        for col in [
            "quality_score", "quality_grade", "category_scores",
            "dependency_graph", "ntia_result", "bsi_result",
            "fsct_result", "oct_result", "policy_result",
        ]:
            batch_op.drop_column(col)

"""add TOTP second factor and capability grants

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-19
"""

from alembic import op
import sqlalchemy as sa


revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── Capability grants ────────────────────────────────────
    # Existing non-admin accounts keep the reach they already had, so an
    # upgrade does not silently lock people out of their own workspaces.
    # New accounts are created with everything off (chat only).
    op.add_column(
        "users",
        sa.Column("can_terminal", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "users",
        sa.Column("can_machine", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "users",
        sa.Column("can_external", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        "UPDATE users SET can_terminal = 1, can_machine = 1, can_external = 1 "
        "WHERE role = 'user'"
    )

    # ── TOTP ─────────────────────────────────────────────────
    op.add_column("auths", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column(
        "auths",
        sa.Column("totp_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "auths",
        sa.Column("totp_reset_required", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("auths", sa.Column("totp_last_used_at", sa.BigInteger(), nullable=True))

    # ── Superadmin ───────────────────────────────────────────
    # The tier is new, so promote the earliest-created admin. Rule 6 says the
    # last remaining admin becomes superadmin automatically; seeding one here
    # keeps that invariant true from the first boot after upgrade.
    op.execute(
        "UPDATE users SET role = 'superadmin' WHERE id = ("
        "  SELECT id FROM users WHERE role = 'admin' ORDER BY created_at LIMIT 1"
        ")"
    )


def downgrade() -> None:
    op.execute("UPDATE users SET role = 'admin' WHERE role = 'superadmin'")
    op.drop_column("auths", "totp_last_used_at")
    op.drop_column("auths", "totp_reset_required")
    op.drop_column("auths", "totp_enabled")
    op.drop_column("auths", "totp_secret")
    op.drop_column("users", "can_external")
    op.drop_column("users", "can_machine")
    op.drop_column("users", "can_terminal")

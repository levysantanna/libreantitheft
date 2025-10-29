"""Add device_configs table for URL persistence

Revision ID: da6060f439f3
Revises: 
Create Date: 2025-10-29 07:23:05.454996

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'da6060f439f3'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create device_configs table
    op.create_table('device_configs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('device_id', sa.String(length=100), nullable=False),
        sa.Column('server_url', sa.String(length=500), nullable=False),
        sa.Column('websocket_url', sa.String(length=500), nullable=True),
        sa.Column('api_endpoint', sa.String(length=500), nullable=True),
        sa.Column('is_configured', sa.Boolean(), nullable=True),
        sa.Column('last_config_update', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=True),
        sa.ForeignKeyConstraint(['device_id'], ['devices.device_id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('device_id')
    )
    op.create_index(op.f('ix_device_configs_id'), 'device_configs', ['id'], unique=False)


def downgrade() -> None:
    # Drop device_configs table
    op.drop_index(op.f('ix_device_configs_id'), table_name='device_configs')
    op.drop_table('device_configs')

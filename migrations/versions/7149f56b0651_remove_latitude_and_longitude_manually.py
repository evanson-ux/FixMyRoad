"""Remove latitude and longitude manually

Revision ID: 7149f56b0651
Revises: e8292713349a
Create Date: 2025-08-20 05:42:13.196763

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7149f56b0651'
down_revision = 'e8292713349a'
branch_labels = None
depends_on = None


def upgrade():
    # Columns already removed manually, so nothing to drop
    pass


def downgrade():
    with op.batch_alter_table('report') as batch_op:
        batch_op.add_column(sa.Column('latitude', sa.Float, nullable=True))
        batch_op.add_column(sa.Column('longitude', sa.Float, nullable=True))

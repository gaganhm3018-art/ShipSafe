"""Initial ShipSafe schema with organizations, users, scans, and recurrence tracking

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-21 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from database.connection import Base

revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Use Base.metadata.create_all for portable DDL across Postgres and SQLite
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

def downgrade() -> None:
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)

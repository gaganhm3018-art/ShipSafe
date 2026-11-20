"""Auth gateway tables for password resets and email verifications

Revision ID: 002_auth_gateway_persistence
Revises: 001_initial_schema
Create Date: 2026-11-21 03:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from database.connection import Base

revision: str = "002_auth_gateway_persistence"
down_revision: Union[str, None] = "001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

def downgrade() -> None:
    pass

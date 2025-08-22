import sys
import os
import logging
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Add the server folder to Python path so imports work
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Alembic Config object
config = context.config

# Logging setup
fileConfig(config.config_file_name)
logger = logging.getLogger('alembic.env')

# --------------------------
# Import your models here
# --------------------------
from app import db               # shared SQLAlchemy instance
from models.report import Report  # import Report model
from models.user import User      # import User model

# Metadata from all models
target_metadata = db.metadata

# --------------------------
# Offline migrations
# --------------------------
def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

# --------------------------
# Online migrations
# --------------------------
def run_migrations_online():
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()

# --------------------------
# Run Alembic
# --------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

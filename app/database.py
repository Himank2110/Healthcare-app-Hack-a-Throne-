from collections.abc import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def apply_local_schema_updates() -> None:
    """Apply small additive updates for this starter's existing local database."""
    additions = {
        "users": {
            "display_name": "VARCHAR(120) NOT NULL DEFAULT ''",
            "username": "VARCHAR(64)",
            "email": "VARCHAR(320)",
            "password_hash": "VARCHAR(255)",
            "token_version": "INTEGER NOT NULL DEFAULT 0",
            "status": "VARCHAR(24) NOT NULL DEFAULT 'active'",
            "requested_role": "VARCHAR(32)",
            "organization_type": "VARCHAR(24)",
            "organization_name": "VARCHAR(160)",
        },
        "patients": {"display_name": "VARCHAR(120) NOT NULL DEFAULT ''"},
        "prescription_shares": {"revoked_at": "DATETIME"},
    }
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table_name, columns in additions.items():
            if not inspector.has_table(table_name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, sql_type in columns.items():
                if column_name not in existing:
                    connection.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {sql_type}")
                    )
        if inspector.has_table("users"):
            connection.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)")
            )
            connection.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username)")
            )


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

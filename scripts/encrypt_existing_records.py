"""Encrypt existing health text before enabling the production data key."""

from cryptography.fernet import Fernet
from sqlalchemy import create_engine, inspect, text

from app.config import settings


PREFIX = "enc:v1:"
SENSITIVE_COLUMNS = {
    "patients": ("display_name",),
    "encounters": ("diagnosis",),
    "prescription_items": ("medicine", "instructions"),
}


def main() -> None:
    if not settings.data_encryption_key:
        raise SystemExit("Set DATA_ENCRYPTION_KEY in the environment before running this migration.")
    try:
        cipher = Fernet(settings.data_encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise SystemExit("DATA_ENCRYPTION_KEY is not a valid Fernet key.") from None

    engine = create_engine(settings.database_url, pool_pre_ping=True)
    encrypted_count = 0
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table, columns in SENSITIVE_COLUMNS.items():
            if not inspector.has_table(table):
                continue
            available = {column["name"] for column in inspector.get_columns(table)}
            if "id" not in available:
                continue
            for column in columns:
                if column not in available:
                    continue
                # Fernet expands data, so widen existing PostgreSQL varchar columns first.
                if connection.dialect.name == "postgresql":
                    connection.execute(text(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE TEXT"))
                rows = connection.execute(text(f"SELECT id, {column} FROM {table}")).all()
                for row_id, value in rows:
                    if value is None or value.startswith(PREFIX):
                        continue
                    encrypted = PREFIX + cipher.encrypt(value.encode("utf-8")).decode("ascii")
                    connection.execute(
                        text(f"UPDATE {table} SET {column} = :value WHERE id = :row_id"),
                        {"value": encrypted, "row_id": row_id},
                    )
                    encrypted_count += 1
    engine.dispose()
    print(f"Encrypted {encrypted_count} existing health-data fields.")
    print("Keep DATA_ENCRYPTION_KEY backed up separately from the database; losing it makes these fields unreadable.")


if __name__ == "__main__":
    main()

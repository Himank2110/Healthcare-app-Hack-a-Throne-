from pydantic_settings import BaseSettings, SettingsConfigDict
from cryptography.fernet import Fernet


class Settings(BaseSettings):
    database_url: str = "sqlite:///./healthcare-dev.db"
    jwt_secret: str = "development-only-change-me"
    jwt_algorithm: str = "HS256"
    app_env: str = "development"
    enable_dev_auth: bool = False
    bootstrap_admin_key: str = ""
    data_encryption_key: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_starttls: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()


def validate_runtime_security(config: Settings = settings) -> None:
    """Fail closed for security settings when the app is not running locally."""
    if config.app_env.strip().lower() == "development":
        return
    if config.enable_dev_auth:
        raise RuntimeError("ENABLE_DEV_AUTH must be false outside development")
    if (
        len(config.jwt_secret.encode("utf-8")) < 32
        or config.jwt_secret == "development-only-change-me"
        or "replace-with" in config.jwt_secret.lower()
        or "change-me" in config.jwt_secret.lower()
    ):
        raise RuntimeError("Set JWT_SECRET to a unique random value of at least 32 bytes")
    if not config.data_encryption_key:
        raise RuntimeError("Set DATA_ENCRYPTION_KEY outside development")
    try:
        Fernet(config.data_encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        raise RuntimeError("DATA_ENCRYPTION_KEY must be a valid Fernet key") from None
    if not config.smtp_host or not config.smtp_from:
        raise RuntimeError("Configure SMTP_HOST and SMTP_FROM outside development for password recovery")
    if not 1 <= config.smtp_port <= 65535 or not config.smtp_starttls:
        raise RuntimeError("Configure SMTP with a valid port and STARTTLS enabled")
    if bool(config.smtp_username) != bool(config.smtp_password):
        raise RuntimeError("Configure both SMTP_USERNAME and SMTP_PASSWORD, or neither")

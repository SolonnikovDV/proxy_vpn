from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "proxy-vpn"
    database_url: str = "sqlite:///./data/app.db"
    app_secret_key: str = "change-me-in-production"
    app_secret_key_file: str = ""
    session_max_age_seconds: int = 86400
    admin_username: str = "admin"
    admin_email: str = "admin@local"
    admin_password: str = "admin123!"
    admin_password_file: str = ""


def _read_secret_from_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()
    if not value:
        raise ValueError(f"Secret file is empty: {path}")
    return value


settings = Settings()

if settings.app_secret_key_file:
    settings.app_secret_key = _read_secret_from_file(settings.app_secret_key_file)

if settings.admin_password_file:
    settings.admin_password = _read_secret_from_file(settings.admin_password_file)

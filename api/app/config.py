from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "proxy-vpn"
    database_url: str = "sqlite:///./data/app.db"
    app_secret_key: str = "change-me-in-production"
    session_max_age_seconds: int = 86400
    admin_username: str = "admin"
    admin_email: str = "admin@local"
    admin_password: str = "admin123!"


settings = Settings()

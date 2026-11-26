"""Environment-based configuration for Q-SHIELD backend."""

from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    app_name: str = "Q-SHIELD Control Plane"
    app_version: str = "0.2.0"
    environment: str = "local"
    enable_dev_demo_auth: bool = False
    database_url: str = "sqlite:///./qshield.db"
    log_level: str = "INFO"
    session_ttl_seconds: int = 3600
    key_store_dir: str = ".qshield_keys"
    master_key_b64: str | None = None
    upload_dir: str = ".qshield_uploads"
    max_upload_bytes: int = 10 * 1024 * 1024 * 1024
    storage_quota_bytes: int = 50 * 1024 * 1024 * 1024
    worker_poll_seconds: float = 0.5

    model_config = SettingsConfigDict(
        env_prefix="QSHIELD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()

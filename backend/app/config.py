"""Environment-based configuration for Q-SHIELD backend."""

from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import tempfile

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _is_readonly_or_vercel() -> bool:
    """Detect Vercel serverless or read-only working directory."""
    if os.getenv("VERCEL"):
        return True
    try:
        return not os.access(".", os.W_OK)
    except OSError:
        return True


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

    @model_validator(mode="after")
    def _apply_serverless_defaults(self) -> Settings:
        # Allow standard DATABASE_URL (e.g. Vercel Postgres / Supabase / Neon) when QSHIELD_DATABASE_URL is unset/empty
        if not os.getenv("QSHIELD_DATABASE_URL"):
            generic_db = os.getenv("DATABASE_URL")
            if generic_db:
                self.database_url = generic_db
            elif not self.database_url or (_is_readonly_or_vercel() and self.database_url == "sqlite:///./qshield.db"):
                if _is_readonly_or_vercel():
                    tmp_db = (Path(tempfile.gettempdir()) / "qshield.db").as_posix()
                    self.database_url = f"sqlite:///{tmp_db}"
                else:
                    self.database_url = "sqlite:///./qshield.db"

        if self.database_url.startswith("postgres://"):
            self.database_url = "postgresql://" + self.database_url[len("postgres://") :]

        if _is_readonly_or_vercel():
            tmp_root = Path(tempfile.gettempdir())
            if not os.getenv("QSHIELD_KEY_STORE_DIR") and self.key_store_dir == ".qshield_keys":
                self.key_store_dir = str(tmp_root / ".qshield_keys")
            if not os.getenv("QSHIELD_UPLOAD_DIR") and self.upload_dir == ".qshield_uploads":
                self.upload_dir = str(tmp_root / ".qshield_uploads")
            if not os.getenv("QSHIELD_ENVIRONMENT") and self.environment == "local":
                self.environment = "production"
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings."""
    return Settings()

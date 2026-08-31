from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    environment: str = Field(default="dev", alias="THREATFUSION_ENV")
    log_level: str = Field(default="INFO", alias="THREATFUSION_LOG_LEVEL")

    database_url: str = Field(
        default="sqlite:///./data/processed/threatfusion_dev.sqlite3",
        alias="DATABASE_URL",
    )

    gemini_enabled: bool = Field(default=False, alias="GEMINI_ENABLED")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-configured-at-runtime", alias="GEMINI_MODEL")

    abuseipdb_enabled: bool = Field(default=False, alias="ABUSEIPDB_ENABLED")
    abuseipdb_api_key: str | None = Field(default=None, alias="ABUSEIPDB_API_KEY")

    project_root: Path = Path(__file__).resolve().parents[4]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()

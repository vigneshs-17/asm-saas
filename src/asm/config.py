"""Application configuration loaded from environment variables."""

import sys
from functools import lru_cache

from pydantic import Field, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for ASM SaaS services."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # DATABASE_URL is required with NO default. Fails startup if missing.
    database_url: str = Field(
        ...,
        description=(
            "PostgreSQL connection string "
            "(e.g. postgresql+psycopg://user:pass@host:5432/dbname)"
        ),
    )
    test_database_url: str | None = Field(
        default=None,
        description="Optional PostgreSQL connection string for test suite (must end in _test)",
    )
    supabase_publishable_key: str = Field(
        default="",
        description="Public non-secret Supabase publishable key for browser client authentication",
    )

    @field_validator("supabase_publishable_key")
    @classmethod
    def validate_publishable_key(cls, v: str) -> str:
        cleaned = v.strip()
        if cleaned.startswith("sb_secret_"):
            raise ValueError(
                "CRITICAL SECURITY MISCONFIGURATION: SUPABASE_PUBLISHABLE_KEY "
                "contains a secret service key ('sb_secret_...'). "
                "Only the public publishable/anon key may be configured."
            )
        return cleaned


@lru_cache
def get_settings() -> Settings:
    """Retrieve validated application settings or exit with a clear message."""
    try:
        return Settings()  # type: ignore[call-arg]
    except ValidationError as err:
        for error in err.errors():
            if error.get("loc") and error["loc"][0] == "supabase_publishable_key":
                msg = error.get("msg", "Invalid SUPABASE_PUBLISHABLE_KEY")
                raise RuntimeError(
                    f"CRITICAL SECURITY MISCONFIGURATION: {msg}"
                ) from err
        missing_fields = [
            error["loc"][0]
            for error in err.errors()
            if error["type"] == "missing"
        ]
        if "database_url" in missing_fields:
            sys.stderr.write(
                "Configuration Error: DATABASE_URL environment variable is required but not set.\n"
                "Please configure DATABASE_URL in your environment or .env file.\n"
            )
            raise RuntimeError(
                "DATABASE_URL environment variable is required but not set."
            ) from err
        raise

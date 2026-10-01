"""Authentication configuration for Supabase integration."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthSettings:
    """Settings for Supabase JWT verification."""

    supabase_url: str = ""
    jwt_audience: str = "authenticated"
    jwks_fetch_timeout: float = 5.0
    jwks_min_refresh_interval: float = 10.0
    jwks_cache_ttl: float = 3600.0

    @property
    def is_configured(self) -> bool:
        """Return True if SUPABASE_URL is set and non-empty."""
        return bool(self.supabase_url and self.supabase_url.strip())

    @property
    def jwks_url(self) -> str:
        """Derive the standard Supabase JWKS endpoint URL."""
        if not self.is_configured:
            return ""
        return f"{self.supabase_url.rstrip('/')}/auth/v1/.well-known/jwks.json"

    @property
    def expected_issuer(self) -> str:
        """Derive the expected JWT issuer claim."""
        if not self.is_configured:
            return ""
        return f"{self.supabase_url.rstrip('/')}/auth/v1"


def get_auth_settings() -> AuthSettings:
    """Load authentication settings from environment variables."""
    supabase_url = os.getenv("SUPABASE_URL", "").strip()
    jwt_audience = os.getenv("JWT_AUDIENCE", "authenticated").strip() or "authenticated"
    return AuthSettings(
        supabase_url=supabase_url,
        jwt_audience=jwt_audience,
    )

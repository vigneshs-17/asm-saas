"""JWKS key retrieval, caching, and rate-limited refresh."""

import logging
import threading
import time
from typing import Any

import httpx
from jwt import PyJWK, PyJWKSet

logger = logging.getLogger(__name__)


class JWKSUnavailableError(Exception):
    """Raised when the upstream JWKS endpoint cannot be reached."""

    pass


class JWKSManager:
    """Manages fetching, caching, and explicit throttled refresh of JWKS keys."""

    def __init__(
        self,
        jwks_url: str,
        fetch_timeout: float = 5.0,
        min_refresh_interval: float = 10.0,
        cache_ttl: float = 3600.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self.jwks_url = jwks_url
        self.fetch_timeout = fetch_timeout
        self.min_refresh_interval = min_refresh_interval
        self.cache_ttl = cache_ttl
        self._http_client = http_client

        self._keys: dict[str, PyJWK] = {}
        self._last_fetch_time: float = 0.0
        self._lock = threading.Lock()

    def _fetch_jwks(self) -> dict[str, Any]:
        """Perform an HTTP GET request to the JWKS URL with strict 5s timeout."""
        try:
            if self._http_client is not None:
                resp = self._http_client.get(self.jwks_url, timeout=self.fetch_timeout)
            else:
                with httpx.Client(timeout=self.fetch_timeout) as client:
                    resp = client.get(self.jwks_url)

            if resp.status_code >= 400:
                logger.error("JWKS endpoint returned error status code: %d", resp.status_code)
                raise JWKSUnavailableError(
                    f"JWKS endpoint returned status code {resp.status_code}"
                )

            return resp.json()
        except httpx.RequestError as exc:
            logger.error("Network error reaching JWKS endpoint: %s", exc)
            raise JWKSUnavailableError(f"JWKS endpoint unreachable: {exc}") from exc
        except Exception as exc:
            if isinstance(exc, JWKSUnavailableError):
                raise
            logger.error("Unexpected error fetching JWKS: %s", exc)
            raise JWKSUnavailableError(f"Unexpected error fetching JWKS: {exc}") from exc

    def _load_keys_from_jwks(self, jwks_data: dict[str, Any]) -> None:
        """Parse JWKS dictionary and populate internal key cache."""
        jwk_set = PyJWKSet.from_dict(jwks_data)
        new_keys: dict[str, PyJWK] = {}
        for key in jwk_set.keys:
            if key.key_id:
                new_keys[key.key_id] = key
        self._keys = new_keys
        self._last_fetch_time = time.monotonic()

    def get_signing_key(self, kid: str) -> PyJWK | None:
        """Retrieve a PyJWK signing key by kid, refreshing cache if needed and not throttled."""
        now = time.monotonic()

        # 1. Fast read from existing cache if not expired
        if kid in self._keys and (now - self._last_fetch_time < self.cache_ttl):
            return self._keys[kid]

        # 2. Key missing or cache expired: acquire lock to refresh
        with self._lock:
            now = time.monotonic()
            # Double-check inside lock
            if kid in self._keys and (now - self._last_fetch_time < self.cache_ttl):
                return self._keys[kid]

            # Enforce throttle: do not fetch if we refreshed too recently
            if (now - self._last_fetch_time) < self.min_refresh_interval and self._keys:
                logger.warning(
                    "JWKS refresh for unknown kid '%s' throttled "
                    "(last fetch %.2fs ago, min interval %.2fs)",
                    kid,
                    now - self._last_fetch_time,
                    self.min_refresh_interval,
                )
                return None

            # 3. Perform fetch
            jwks_data = self._fetch_jwks()
            self._load_keys_from_jwks(jwks_data)

            # Return key if found after refresh
            return self._keys.get(kid)

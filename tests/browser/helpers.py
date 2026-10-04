"""Helper utilities, synthetic JWT generation, and token registries for browser tests."""

from __future__ import annotations

import base64
import json
import time
from uuid import UUID

from playwright.sync_api import Page

from asm.db.models import User

# Map of synthetic access_token string -> user.id
TOKEN_REGISTRY: dict[str, UUID] = {}

# Map of synthetic refresh_token string -> user.id
REFRESH_REGISTRY: dict[str, UUID] = {}


def make_fake_jwt(user: User) -> str:
    """Build a synthetic JWT-shaped string for a User and register it."""
    def _b64url(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    header = _b64url({"alg": "HS256", "typ": "JWT"})
    payload = _b64url(
        {
            "sub": str(user.id),
            "email": user.email,
            "aud": "authenticated",
            "role": "authenticated",
            "exp": int(time.time()) + 3600,
        }
    )
    token = f"{header}.{payload}.synthetic_signature"
    TOKEN_REGISTRY[token] = user.id
    return token


def sign_in(page: Page, email: str, base_url: str) -> None:
    """Helper to perform UI sign-in via #signin-form and wait for app shell."""
    page.goto(f"{base_url}/app")
    page.locator("#signin-email").fill(email)
    page.locator("#signin-password").fill("ValidPassword123!")
    page.locator('#signin-form button[type="submit"]').click()
    page.locator("#app-shell").wait_for(state="visible")

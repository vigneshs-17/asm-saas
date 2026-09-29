"""Shared pytest fixtures for ASM SaaS test suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


@pytest.fixture
def crtsh_sample_data() -> list[dict[str, Any]]:
    """Load the realistic crt.sh JSON fixture."""
    fixture_path = Path(__file__).parent / "fixtures" / "crtsh_sample.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(autouse=True)
def mock_sleep():
    """Autouse fixture to mock time.sleep across tests so no test actually waits."""
    with patch("time.sleep", return_value=None) as mocked:
        yield mocked

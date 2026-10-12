"""Global pytest test configuration and fixtures."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from log_corr.config.settings import Settings, get_settings


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory for isolation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_settings(temp_dir: Path) -> Settings:
    """Provide isolated test settings."""
    settings = Settings(
        environment="testing",
        db_path=temp_dir / "test_correlation.db",
        alert_output_file=temp_dir / "test_alerts.jsonl",
        default_window_seconds=10,
        max_events_per_window=100,
    )
    # Clear lru_cache for settings
    get_settings.cache_clear()
    return settings

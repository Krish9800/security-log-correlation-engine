"""Unit tests for foundational project configuration and settings."""

from pathlib import Path

from log_corr import __author__, __version__
from log_corr.config.settings import Settings, get_settings


def test_package_metadata() -> None:
    """Verify package metadata attributes."""
    assert __version__ == "0.1.0"
    assert "Cybersecurity" in __author__


def test_default_settings_initialization() -> None:
    """Verify default Settings instance attributes."""
    settings = Settings()
    assert settings.app_name == "Security Log Correlation Engine"
    assert settings.app_version == "0.1.0"
    assert settings.default_window_seconds == 60
    assert settings.max_events_per_window == 10000
    assert settings.cleanup_interval_seconds == 30
    assert settings.max_incident_history == 5000
    assert settings.enable_wal_mode is True
    assert settings.api_port == 8000
    assert settings.api_prefix == "/api/v1"
    assert settings.enable_console_alerts is True
    assert settings.webhook_url is None
    assert settings.db_path == Path("data/correlation_engine.db")


def test_custom_settings_initialization(temp_dir: Path) -> None:
    """Verify custom settings overrides."""
    custom_db = temp_dir / "custom.db"
    settings = Settings(
        environment="staging",
        default_window_seconds=120,
        db_path=custom_db,
        webhook_url="https://hooks.example.com/alerts",
    )
    assert settings.environment == "staging"
    assert settings.default_window_seconds == 120
    assert settings.db_path == custom_db
    assert settings.webhook_url == "https://hooks.example.com/alerts"


def test_settings_singleton_caching() -> None:
    """Verify get_settings returns a cached instance."""
    get_settings.cache_clear()
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2


def test_env_var_override(monkeypatch: object) -> None:
    """Verify environment variables prefix LOG_CORR_ overrides defaults."""
    import pytest

    mp = pytest.MonkeyPatch()
    mp.setenv("LOG_CORR_DEFAULT_WINDOW_SECONDS", "300")
    mp.setenv("LOG_CORR_ENVIRONMENT", "production")

    settings = Settings()
    assert settings.default_window_seconds == 300
    assert settings.environment == "production"
    mp.undo()

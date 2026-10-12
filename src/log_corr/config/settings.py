"""Runtime configuration settings for Security Log Correlation Engine."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Operational settings for the log correlation engine."""

    model_config = SettingsConfigDict(
        env_prefix="LOG_CORR_",
        env_file=".env",
        extra="ignore",
    )

    # Core Application Metadata
    app_name: str = "Security Log Correlation Engine"
    app_version: str = "0.1.0"
    environment: str = "development"
    log_level: str = "INFO"

    # Engine Sliding Window Parameters
    default_window_seconds: int = 60
    max_events_per_window: int = 10000
    cleanup_interval_seconds: int = 30
    max_incident_history: int = 5000

    # Persistence Settings
    db_path: Path = Path("data/correlation_engine.db")
    enable_wal_mode: bool = True

    # Control Plane API Settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_prefix: str = "/api/v1"
    secret_key: str = "dev-insecure-secret-key-change-in-production"

    # Notification & Alerting Channels
    enable_console_alerts: bool = True
    webhook_url: str | None = None
    alert_output_file: Path | None = Path("data/alerts.jsonl")


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()

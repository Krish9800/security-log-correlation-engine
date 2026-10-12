"""FastAPI Control Plane for Security Log Correlation Engine."""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query, status
from pydantic import BaseModel, Field

from log_corr.alerts.dispatcher import AlertDispatcher
from log_corr.config.settings import Settings, get_settings
from log_corr.db.database import DatabaseManager
from log_corr.engine.correlator import CorrelationEngine
from log_corr.ingestion.dispatcher import LogIngestionDispatcher
from log_corr.models.enums import IncidentStatus
from log_corr.models.schemas import AlertNotification, CorrelatedIncident, CorrelationRule
from log_corr.rules.rule_catalog import get_default_rules


class LogIngestRequest(BaseModel):
    """Payload for log ingestion endpoint."""

    logs: list[str] = Field(default_factory=list, description="List of raw log strings")
    log: str | None = Field(default=None, description="Optional single log line")


class LogIngestResponse(BaseModel):
    """Response payload for log ingestion endpoint."""

    ingested_count: int
    incidents_count: int
    incidents: list[CorrelatedIncident]


class IncidentStatusUpdate(BaseModel):
    """Payload for updating incident lifecycle status."""

    status: IncidentStatus


class HealthResponse(BaseModel):
    """Health check status response."""

    status: str
    app_name: str
    app_version: str
    timestamp: str
    active_rules_count: int
    active_keys_count: int


def create_app(
    settings: Settings | None = None,
    db: DatabaseManager | None = None,
    engine: CorrelationEngine | None = None,
    dispatcher: AlertDispatcher | None = None,
) -> FastAPI:
    """Factory creating and configuring the FastAPI application."""
    active_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        # Initialize dependencies if not injected
        if not hasattr(app.state, "db"):
            app.state.db = db or DatabaseManager(active_settings.db_path)
        if not hasattr(app.state, "engine"):
            app.state.engine = engine or CorrelationEngine(
                cooldown_seconds=active_settings.cleanup_interval_seconds
            )
            # Register built-in rules if none registered
            if not app.state.engine.list_rules():
                for rule in get_default_rules():
                    app.state.engine.register_rule(rule)
                    app.state.db.save_rule(rule)
        if not hasattr(app.state, "dispatcher"):
            app.state.dispatcher = dispatcher or AlertDispatcher(
                enable_console=active_settings.enable_console_alerts,
                output_file=active_settings.alert_output_file,
                webhook_url=active_settings.webhook_url,
            )
        if not hasattr(app.state, "ingestion_dispatcher"):
            app.state.ingestion_dispatcher = LogIngestionDispatcher()
        yield
        # Teardown
        if hasattr(app.state, "db") and app.state.db:
            app.state.db.close()

    app = FastAPI(
        title=active_settings.app_name,
        version=active_settings.app_version,
        lifespan=lifespan,
    )

    # Attach initial state if pre-constructed
    if db is not None:
        app.state.db = db
    if engine is not None:
        app.state.engine = engine
    if dispatcher is not None:
        app.state.dispatcher = dispatcher
    app.state.ingestion_dispatcher = LogIngestionDispatcher()

    # ------------------------------------------------------------------------
    # Health Endpoint
    # ------------------------------------------------------------------------

    @app.get("/health", response_model=HealthResponse)
    def health_check() -> HealthResponse:
        """Health check and active correlation telemetry."""
        eng: CorrelationEngine = app.state.engine
        stats = eng.buffer.get_stats()
        return HealthResponse(
            status="ok",
            app_name=active_settings.app_name,
            app_version=active_settings.app_version,
            timestamp=datetime.now(timezone.utc).isoformat(),
            active_rules_count=len(eng.list_rules(enabled_only=True)),
            active_keys_count=int(stats["active_keys"]),
        )

    # ------------------------------------------------------------------------
    # Ingestion Endpoint
    # ------------------------------------------------------------------------

    @app.post("/api/v1/logs/ingest", response_model=LogIngestResponse)
    def ingest_logs(payload: LogIngestRequest) -> LogIngestResponse:
        """Ingest raw log strings, parse into normalized events, correlate, and persist."""
        lines_to_process = list(payload.logs)
        if payload.log:
            lines_to_process.append(payload.log)

        if not lines_to_process:
            return LogIngestResponse(ingested_count=0, incidents_count=0, incidents=[])

        ingestion: LogIngestionDispatcher = app.state.ingestion_dispatcher
        corr_engine: CorrelationEngine = app.state.engine
        database: DatabaseManager = app.state.db
        alert_disp: AlertDispatcher = app.state.dispatcher

        normalized_events = ingestion.parse_lines(lines_to_process)
        database.save_events(normalized_events)

        all_incidents: list[CorrelatedIncident] = []
        for event in normalized_events:
            incidents = corr_engine.process_event(event)
            for inc in incidents:
                database.save_incident(inc)
                alert = alert_disp.dispatch(inc)
                database.save_alert(alert)
                all_incidents.append(inc)

        return LogIngestResponse(
            ingested_count=len(normalized_events),
            incidents_count=len(all_incidents),
            incidents=all_incidents,
        )

    # ------------------------------------------------------------------------
    # Incident Endpoints
    # ------------------------------------------------------------------------

    @app.get("/api/v1/incidents", response_model=list[CorrelatedIncident])
    def list_incidents(
        status: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[CorrelatedIncident]:
        """Query persisted security incidents."""
        database: DatabaseManager = app.state.db
        return database.list_incidents(status=status, severity=severity, limit=limit)

    @app.get("/api/v1/incidents/{incident_id}", response_model=CorrelatedIncident)
    def get_incident(incident_id: str) -> CorrelatedIncident:
        """Retrieve details of a single incident by ID."""
        database: DatabaseManager = app.state.db
        incident = database.get_incident(incident_id)
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found",
            )
        return incident

    @app.patch("/api/v1/incidents/{incident_id}/status", response_model=dict[str, str])
    def update_incident_status(incident_id: str, payload: IncidentStatusUpdate) -> dict[str, str]:
        """Update operational status of an incident."""
        database: DatabaseManager = app.state.db
        updated = database.update_incident_status(incident_id, payload.status)
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident {incident_id} not found",
            )
        return {"incident_id": incident_id, "status": payload.status.value}

    # ------------------------------------------------------------------------
    # Rules Endpoints
    # ------------------------------------------------------------------------

    @app.get("/api/v1/rules", response_model=list[CorrelationRule])
    def list_rules(enabled_only: bool = Query(default=False)) -> list[CorrelationRule]:
        """List active correlation rules."""
        corr_engine: CorrelationEngine = app.state.engine
        return corr_engine.list_rules(enabled_only=enabled_only)

    @app.post("/api/v1/rules", response_model=dict[str, str], status_code=status.HTTP_201_CREATED)
    def register_rule(rule: CorrelationRule) -> dict[str, str]:
        """Register a new correlation rule."""
        corr_engine: CorrelationEngine = app.state.engine
        database: DatabaseManager = app.state.db
        corr_engine.register_rule(rule)
        database.save_rule(rule)
        return {"rule_id": rule.rule_id, "status": "created"}

    @app.delete("/api/v1/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
    def delete_rule(rule_id: str) -> None:
        """Delete and unregister a correlation rule."""
        corr_engine: CorrelationEngine = app.state.engine
        database: DatabaseManager = app.state.db
        removed_from_engine = corr_engine.unregister_rule(rule_id)
        removed_from_db = database.delete_rule(rule_id)
        if not removed_from_engine and not removed_from_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule {rule_id} not found",
            )

    # ------------------------------------------------------------------------
    # Alerts Endpoints
    # ------------------------------------------------------------------------

    @app.get("/api/v1/alerts", response_model=list[AlertNotification])
    def list_alerts(limit: int = Query(default=100, ge=1, le=1000)) -> list[AlertNotification]:
        """List dispatched alert notifications."""
        database: DatabaseManager = app.state.db
        return database.list_alerts(limit=limit)

    return app


app = create_app()

"""Command-line interface for Security Log Correlation Engine using Typer and Rich."""

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from log_corr import __version__
from log_corr.alerts.dispatcher import AlertDispatcher
from log_corr.config.settings import get_settings
from log_corr.db.database import DatabaseManager
from log_corr.engine.correlator import CorrelationEngine
from log_corr.ingestion.dispatcher import LogIngestionDispatcher
from log_corr.models.enums import LogFormat
from log_corr.rules.rule_catalog import RuleLoader, get_default_rules

app = typer.Typer(
    name="log-corr",
    help="Security Log Correlation Engine CLI for multi-stage threat detection.",
    no_args_is_help=True,
)
console = Console()


@app.command("version")
def show_version() -> None:
    """Display engine version."""
    console.print(f"[bold green]Security Log Correlation Engine[/bold green] v{__version__}")


@app.command("ingest")
def ingest_file(
    file_path: Path = typer.Argument(..., help="Path to raw log file to ingest"),
    format_hint: str = typer.Option(
        "auto", "--format", "-f", help="Log format: auto, syslog, cef, json, windows_event"
    ),
    db_path: Path = typer.Option(
        None, "--db", help="Target SQLite database file path (defaults to settings)"
    ),
) -> None:
    """Parse raw log lines and store normalized events into database."""
    settings = get_settings()
    active_db = db_path or settings.db_path
    if not file_path.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise typer.Exit(code=1)

    hint = LogFormat(format_hint) if format_hint != "auto" else None
    dispatcher = LogIngestionDispatcher()
    db = DatabaseManager(active_db)

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        events = [dispatcher.parse(line, format_hint=hint) for line in lines if line.strip()]
        saved = db.save_events(events)
        console.print(
            f"[bold green]Successfully ingested {saved} events[/bold green] into {active_db}"
        )
    finally:
        db.close()


@app.command("correlate")
def correlate_file(
    file_path: Path = typer.Argument(..., help="Path to log file to analyze"),
    rules_dir: Path = typer.Option(
        None, "--rules-dir", "-r", help="Optional directory containing YAML correlation rules"
    ),
    cooldown: int = typer.Option(0, "--cooldown", "-c", help="Incident cooldown window in seconds"),
    output_alerts: Path = typer.Option(
        None, "--output-alerts", "-o", help="Append alert JSON records to file"
    ),
) -> None:
    """Stream log file through the correlation engine and report detected multi-stage incidents."""
    if not file_path.is_file():
        console.print(f"[bold red]Error:[/bold red] File not found: {file_path}")
        raise typer.Exit(code=1)

    # Initialize rules
    rules = get_default_rules()
    if rules_dir and rules_dir.is_dir():
        custom_rules = RuleLoader.load_from_directory(rules_dir)
        rules.extend(custom_rules)

    engine = CorrelationEngine(cooldown_seconds=cooldown)
    for r in rules:
        engine.register_rule(r)

    dispatcher = LogIngestionDispatcher()
    alert_disp = AlertDispatcher(enable_console=False, output_file=output_alerts)
    events = dispatcher.parse_file(file_path)

    incidents = engine.process_batch(events)
    for inc in incidents:
        alert_disp.dispatch(inc)

    table = Table(title=f"Detected Security Incidents ({len(incidents)})")
    table.add_column("Incident ID", style="bold cyan")
    table.add_column("Rule Name", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Risk Score", justify="right")
    table.add_column("Events", justify="right")
    table.add_column("Entities", style="dim")

    for inc in incidents:
        sev_color = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }.get(inc.severity.value, "white")

        entities_str = ", ".join(f"{k}={v}" for k, v in inc.entity_keys.items())
        table.add_row(
            inc.incident_id,
            inc.rule_name,
            f"[{sev_color}]{inc.severity.value.upper()}[/{sev_color}]",
            f"{inc.risk_score:.1f}",
            str(inc.event_count),
            entities_str,
        )

    console.print(table)


@app.command("incidents")
def list_incidents_cmd(
    status_filter: str = typer.Option(None, "--status", "-s", help="Filter by status"),
    severity_filter: str = typer.Option(None, "--severity", help="Filter by severity"),
    limit: int = typer.Option(50, "--limit", "-l", help="Max records to return"),
    db_path: Path = typer.Option(None, "--db", help="Target SQLite database file path"),
) -> None:
    """Query persisted security incidents from database."""
    settings = get_settings()
    active_db = db_path or settings.db_path
    db = DatabaseManager(active_db)

    try:
        incidents = db.list_incidents(status=status_filter, severity=severity_filter, limit=limit)
        table = Table(title=f"Stored Incidents in {active_db} ({len(incidents)})")
        table.add_column("ID", style="bold cyan")
        table.add_column("Rule Name", style="white")
        table.add_column("Severity", style="bold")
        table.add_column("Risk Score", justify="right")
        table.add_column("Status", style="green")
        table.add_column("Created At", style="dim")

        for inc in incidents:
            table.add_row(
                inc.incident_id,
                inc.rule_name,
                inc.severity.value.upper(),
                f"{inc.risk_score:.1f}",
                inc.status.value,
                inc.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            )
        console.print(table)
    finally:
        db.close()


@app.command("rules")
def list_rules_cmd(
    rules_dir: Path = typer.Option(
        None, "--dir", "-d", help="Custom YAML rules directory (defaults to built-in)"
    ),
) -> None:
    """Display active correlation rules catalog."""
    rules = get_default_rules()
    if rules_dir and rules_dir.is_dir():
        rules.extend(RuleLoader.load_from_directory(rules_dir))

    table = Table(title=f"Correlation Rules Catalog ({len(rules)})")
    table.add_column("Rule ID", style="bold cyan")
    table.add_column("Name", style="white")
    table.add_column("Type", style="yellow")
    table.add_column("Window (s)", justify="right")
    table.add_column("Severity", style="bold")
    table.add_column("Stages", style="dim")

    for r in rules:
        stages_str = ", ".join(s.value for s in r.attack_stages)
        table.add_row(
            r.rule_id,
            r.name,
            r.rule_type.value,
            str(r.window_seconds),
            r.severity.value.upper(),
            stages_str,
        )
    console.print(table)


if __name__ == "__main__":
    app()

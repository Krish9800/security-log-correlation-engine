"""Integration tests for Typer CLI commands."""

from pathlib import Path

from typer.testing import CliRunner

from log_corr import __version__
from log_corr.cli.main import app

runner = CliRunner()


def test_cli_version() -> None:
    """Verify CLI version command output."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_cli_ingest_and_missing_file(temp_dir: Path) -> None:
    """Verify CLI ingest command persists logs to database and handles missing files."""
    log_file = temp_dir / "sample.log"
    log_file.write_text("Oct 12 12:00:00 srv sshd[1]: auth failure for root from 1.2.3.4\n")
    db_file = temp_dir / "cli_test.db"

    result = runner.invoke(app, ["ingest", str(log_file), "--db", str(db_file)])
    assert result.exit_code == 0
    assert "Successfully ingested 1 events" in result.stdout

    # Missing file
    missing_result = runner.invoke(app, ["ingest", str(temp_dir / "missing.log")])
    assert missing_result.exit_code == 1
    assert "File not found" in missing_result.stdout


def test_cli_correlate(temp_dir: Path) -> None:
    """Verify CLI correlate command runs rules and outputs incidents table."""
    ip = "192.168.1.99"
    lines = [
        f"Oct 12 10:00:0{i} srv sshd[10{i}]: Failed password for root from {ip} port 4000{i} ssh2\n"
        for i in range(5)
    ]
    log_file = temp_dir / "brute.log"
    log_file.write_text("".join(lines))
    alerts_file = temp_dir / "cli_alerts.jsonl"

    result = runner.invoke(
        app,
        ["correlate", str(log_file), "--output-alerts", str(alerts_file)],
    )
    assert result.exit_code == 0
    assert "Detected Security Incidents" in result.stdout
    assert "SSH Password" in result.stdout
    assert alerts_file.is_file()

    # Missing file
    bad_res = runner.invoke(app, ["correlate", str(temp_dir / "nofile.log")])
    assert bad_res.exit_code == 1


def test_cli_incidents_and_rules(temp_dir: Path) -> None:
    """Verify CLI incidents listing and rules catalog table."""
    db_file = temp_dir / "incidents_cli.db"
    # First ingest and correlate to generate an incident in db
    ip = "10.0.0.88"
    lines = [
        f"Oct 12 10:00:0{i} srv sshd[10{i}]: Failed password for root from {ip} port 4000{i} ssh2\n"
        for i in range(5)
    ]
    log_file = temp_dir / "events.log"
    log_file.write_text("".join(lines))

    # Ingest logs into DB
    runner.invoke(app, ["ingest", str(log_file), "--db", str(db_file)])

    # Query incidents
    inc_res = runner.invoke(app, ["incidents", "--db", str(db_file)])
    assert inc_res.exit_code == 0

    # Rules catalog
    rules_res = runner.invoke(app, ["rules"])
    assert rules_res.exit_code == 0
    assert "Correlation Rules Catalog" in rules_res.stdout
    assert "R-SSH-BRUT" in rules_res.stdout

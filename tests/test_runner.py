import json
import sqlite3
import sys
from pathlib import Path
# pyrefly: ignore [missing-import]
import pytest

from reconw.storage.db import init_db
from reconw.storage.repository import create_run
from reconw.tools.runner import (
    ToolExecutionResult,
    ToolNotFoundError,
    ToolRunner,
    is_tool_available,
    require_tool,
    run_tool,
    write_temp_targets,
)


def test_is_tool_available_and_require_tool():
    # Python executable is always present in the current test environment
    python_binary = sys.executable
    assert is_tool_available(python_binary) is True
    assert require_tool(python_binary) == python_binary

    fake_tool = "non_existent_fake_recon_binary_12345"
    assert is_tool_available(fake_tool) is False
    with pytest.raises(ToolNotFoundError):
        require_tool(fake_tool)


def test_write_temp_targets(tmp_path: Path):
    targets = ["example.com", "api.example.com", "admin.example.com"]
    temp_file = write_temp_targets(targets, dir=tmp_path)

    assert temp_file.exists()
    content = temp_file.read_text(encoding="utf-8").splitlines()
    assert content == targets

    # Clean up
    temp_file.unlink(missing_ok=True)


def test_tool_execution_result_ndjson_and_lines():
    ndjson_data = '{"host": "api.example.com", "ip": "1.2.3.4"}\n{"host": "dev.example.com", "ip": "1.2.3.5"}\n'
    result = ToolExecutionResult(
        tool_name="subfinder",
        command=["subfinder", "-d", "example.com"],
        exit_code=0,
        stdout=ndjson_data,
        stderr="",
        duration_seconds=1.23,
        started_at="2026-08-19T00:00:00Z",
        finished_at="2026-08-19T00:00:01Z",
    )

    assert result.is_success is True
    assert len(result.lines()) == 2
    parsed = result.parse_ndjson()
    assert len(parsed) == 2
    assert parsed[0]["host"] == "api.example.com"
    assert parsed[1]["host"] == "dev.example.com"


def test_tool_runner_successful_execution(tmp_path: Path):
    runner = ToolRunner(artifacts_dir=tmp_path / "artifacts")
    # Run a safe python command that outputs NDJSON
    cmd_args = [
        "-c",
        'import sys; print(\'{"host": "test.local", "status": 200}\'); sys.stderr.write("info log\\n")',
    ]
    result = runner.run(
        tool_name=sys.executable,
        args=cmd_args,
        stage_name="test_stage",
        save_stdout_as_artifact=True,
    )

    assert result.is_success is True
    assert result.exit_code == 0
    assert "test.local" in result.stdout
    assert "info log" in result.stderr
    assert result.duration_seconds >= 0.0
    assert result.raw_output_path is not None
    assert result.raw_output_path.exists()

    parsed = result.parse_ndjson()
    assert len(parsed) == 1
    assert parsed[0]["status"] == 200


def test_tool_runner_timeout_handling(tmp_path: Path):
    runner = ToolRunner(artifacts_dir=tmp_path / "artifacts")
    # Run command that sleeps for 3 seconds with a 0.5 second timeout
    cmd_args = ["-c", "import time; time.sleep(3)"]
    result = runner.run(
        tool_name=sys.executable,
        args=cmd_args,
        stage_name="test_timeout",
        timeout=1,
    )

    assert result.is_success is False
    assert result.exit_code == 124
    assert result.error_message is not None
    assert "timed out" in result.error_message


def test_tool_runner_db_provenance_logging(tmp_path: Path, monkeypatch):
    # Setup isolated test database
    db_file = tmp_path / "test_recon.db"
    init_db(db_file)

    # Patch DB_PATH in storage.db and storage.repository
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="RUNNING")
    assert run_id > 0

    runner = ToolRunner(artifacts_dir=tmp_path / "artifacts")
    result = runner.run(
        tool_name=sys.executable,
        args=["-c", "print('db audit test')"],
        stage_name="subdomain_enum",
        run_id=run_id,
    )

    assert result.is_success is True
    assert result.tool_result_id is not None
    assert result.tool_result_id > 0

    # Query the tool_result table directly to verify audit row
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT run_id, stage_name, tool_name, exit_code, command FROM tool_result WHERE id = ?", (result.tool_result_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == run_id
    assert row[1] == "subdomain_enum"
    assert row[2] == sys.executable
    assert row[3] == 0
    assert "db audit test" in row[4]


def test_tool_runner_missing_binary(tmp_path: Path):
    runner = ToolRunner(artifacts_dir=tmp_path / "artifacts")
    result = runner.run(
        tool_name="definitely_not_installed_binary_xyz_99",
        args=["-v"],
        stage_name="missing_tool",
    )

    assert result.is_success is False
    assert result.exit_code == 127
    assert result.error_message is not None
    assert "not found in system PATH" in result.error_message

import sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest
from typer.testing import CliRunner

from reconw.cli import cli
from reconw.pipeline import ReconTargets, build_targets, run_pipeline
from reconw.storage.db import init_db
from reconw.tools.runner import ToolExecutionResult

runner = CliRunner()


def test_build_targets(tmp_path: Path):
    in_file = tmp_path / "inscope.txt"
    out_file = tmp_path / "outscope.txt"
    in_file.write_text("example.com\n*.example.com\n", encoding="utf-8")
    out_file.write_text("blog.example.com\n", encoding="utf-8")

    targets = build_targets(in_file, out_file)
    assert len(targets.in_scope) == 2
    assert "example.com" in targets.in_scope
    assert "*.example.com" in targets.in_scope
    assert targets.out_of_scope == ["blog.example.com"]


def test_run_pipeline_end_to_end_mocked(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_pipeline.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    targets = ReconTargets(in_scope=["example.com", "*.example.com"], out_of_scope=["blog.example.com"])

    # Mock tool executions for all stages
    subfinder_res = ToolExecutionResult(
        tool_name="subfinder",
        command=["subfinder"],
        exit_code=0,
        stdout='{"host": "api.example.com", "input": "example.com"}\n{"host": "blog.example.com"}\n',
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=1,
    )
    dnsx_res = ToolExecutionResult(
        tool_name="dnsx",
        command=["dnsx"],
        exit_code=0,
        stdout='{"host": "api.example.com", "a": ["93.184.216.34"], "status_code": "NOERROR"}\n',
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=2,
    )
    httpx_res = ToolExecutionResult(
        tool_name="httpx",
        command=["httpx"],
        exit_code=0,
        stdout='{"url": "https://api.example.com/admin", "title": "Admin Dashboard", "tech": ["Nginx"], "status_code": 200, "content_length": 1500}\n',
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=3,
    )
    katana_res = ToolExecutionResult(
        tool_name="katana",
        command=["katana"],
        exit_code=0,
        stdout='{"url": "https://api.example.com/v1/auth"}\n',
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=4,
    )

    def mock_run_tool(tool_name, *args, **kwargs):
        if tool_name == "subfinder":
            return subfinder_res
        elif tool_name == "dnsx":
            return dnsx_res
        elif tool_name == "httpx":
            return httpx_res
        elif tool_name == "katana":
            return katana_res
        return subfinder_res

    with patch("reconw.stages.subfinder.run_tool", side_effect=mock_run_tool), \
         patch("reconw.stages.dnsx.run_tool", side_effect=mock_run_tool), \
         patch("reconw.stages.httpx.run_tool", side_effect=mock_run_tool), \
         patch("reconw.stages.katana.run_tool", side_effect=mock_run_tool):

        summary = run_pipeline(
            targets=targets,
            cli_args="test",
            generate_report=True,
            reports_dir=tmp_path / "reports",
        )

    assert summary.subdomains_count == 1
    assert summary.resolved_hosts_count >= 1
    assert summary.live_endpoints_count == 1
    assert summary.crawled_urls_count == 1
    assert summary.critical_count + summary.high_count >= 1
    assert summary.report_path is not None
    assert summary.report_path.exists()

    # Verify run completed in DB
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT status FROM run WHERE id = ?", (summary.run_id,))
    row = cursor.fetchone()
    conn.close()

    assert row is not None
    assert row[0] == "COMPLETED"


def test_cli_doctor_command():
    res = runner.invoke(cli, ["doctor"])
    assert res.exit_code == 0
    assert "ReconW Dependency Health Check" in res.stdout


def test_cli_list_runs_command(tmp_path: Path):
    db_file = tmp_path / "test_cli.db"
    init_db(db_file)

    res = runner.invoke(cli, ["list-runs", "-d", str(db_file)])
    assert res.exit_code == 0
    assert "No runs found" in res.stdout

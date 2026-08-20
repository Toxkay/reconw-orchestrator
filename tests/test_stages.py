import sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest

from reconw.scope.validator import ScopeEvaluator
from reconw.stages.dnsx import run_dnsx
from reconw.stages.httpx import run_httpx
from reconw.stages.katana import run_katana
from reconw.storage.db import init_db
from reconw.storage.repository import create_run
from reconw.tools.runner import ToolExecutionResult


def test_run_dnsx_stage(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_dnsx.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="RUNNING")
    evaluator = ScopeEvaluator(in_scope=["example.com", "*.example.com"], out_of_scope=["blog.example.com"])

    mock_dnsx_stdout = (
        '{"host": "api.example.com", "a": ["93.184.216.34"], "status_code": "NOERROR"}\n'
        '{"host": "blog.example.com", "a": ["93.184.216.35"], "status_code": "NOERROR"}\n'
    )

    mock_result = ToolExecutionResult(
        tool_name="dnsx",
        command=["dnsx", "-l", "hosts.txt"],
        exit_code=0,
        stdout=mock_dnsx_stdout,
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=101,
    )

    with patch("reconw.stages.dnsx.run_tool", return_value=mock_result):
        live_hosts = run_dnsx(
            hostnames=["api.example.com", "blog.example.com"],
            run_id=run_id,
            scope_evaluator=evaluator,
        )

    # blog.example.com is out-of-scope, so only api.example.com is returned
    assert live_hosts == ["api.example.com"]

    # Verify DB records in dns_record table
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT record_type, value, source_tool_result_id FROM dns_record")
    records = cursor.fetchall()
    conn.close()

    assert len(records) == 1
    assert records[0] == ("A", "93.184.216.34", 101)


def test_run_httpx_stage(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_httpx.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="RUNNING")
    evaluator = ScopeEvaluator(in_scope=["example.com", "*.example.com"])

    mock_httpx_stdout = (
        '{"url": "https://api.example.com", "title": "API Gateway", "tech": ["Nginx"], "status_code": 200, "content_length": 1024}\n'
    )

    mock_result = ToolExecutionResult(
        tool_name="httpx",
        command=["httpx", "-l", "hosts.txt"],
        exit_code=0,
        stdout=mock_httpx_stdout,
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=102,
    )

    with patch("reconw.stages.httpx.run_tool", return_value=mock_result):
        live_urls = run_httpx(
            targets=["api.example.com"],
            run_id=run_id,
            scope_evaluator=evaluator,
            screenshots_dir=tmp_path / "screenshots",
        )

    assert live_urls == ["https://api.example.com"]

    # Verify DB endpoint row
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT url, status_code, title, tech_stack_json FROM endpoint")
    endpoints = cursor.fetchall()
    conn.close()

    assert len(endpoints) == 1
    assert endpoints[0][0] == "https://api.example.com"
    assert endpoints[0][1] == 200
    assert endpoints[0][2] == "API Gateway"
    assert "Nginx" in endpoints[0][3]


def test_run_katana_stage(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_katana.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="RUNNING")
    evaluator = ScopeEvaluator(in_scope=["example.com", "*.example.com"])

    mock_katana_stdout = (
        '{"request": {"endpoint": "https://api.example.com/v1/users", "tag": "script"}}\n'
        '{"url": "https://api.example.com/v1/auth"}\n'
    )

    mock_result = ToolExecutionResult(
        tool_name="katana",
        command=["katana", "-u", "seeds.txt"],
        exit_code=0,
        stdout=mock_katana_stdout,
        stderr="",
        duration_seconds=1.0,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=103,
    )

    with patch("reconw.stages.katana.run_tool", return_value=mock_result):
        crawled = run_katana(
            seed_urls=["https://api.example.com"],
            run_id=run_id,
            scope_evaluator=evaluator,
        )

    assert len(crawled) == 2
    assert "https://api.example.com/v1/users" in crawled
    assert "https://api.example.com/v1/auth" in crawled

    # Verify DB url_item rows
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT url, source_tool_result_id FROM url_item ORDER BY url")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0] == ("https://api.example.com/v1/auth", 103)
    assert rows[1] == ("https://api.example.com/v1/users", 103)

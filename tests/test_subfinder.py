import sqlite3
from pathlib import Path
from unittest.mock import patch
import pytest

from reconw.scope.validator import ScopeEvaluator
from reconw.stages.subfinder import extract_root_domains, run_subfinder
from reconw.storage.db import init_db
from reconw.storage.repository import create_run
from reconw.tools.runner import ToolExecutionResult


def test_extract_root_domains():
    inputs = ["*.example.com", "example.com", "  HTTPS://API.TARGET.ORG:443  ", "sub.dev.com."]
    extracted = extract_root_domains(inputs)
    assert "example.com" in extracted
    assert "api.target.org" in extracted
    assert "sub.dev.com" in extracted


def test_run_subfinder_with_mocked_output(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_subfinder.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="RUNNING")

    in_scope = ["example.com", "*.example.com"]
    out_of_scope = ["blog.example.com"]
    evaluator = ScopeEvaluator(in_scope=in_scope, out_of_scope=out_of_scope)

    mock_ndjson = (
        '{"host": "api.example.com", "input": "example.com", "sources": ["crtsh"]}\n'
        '{"host": "blog.example.com", "input": "example.com", "sources": ["virustotal"]}\n'
        '{"host": "dev.example.com", "input": "example.com", "sources": ["alienvault"]}\n'
    )

    mock_result = ToolExecutionResult(
        tool_name="subfinder",
        command=["subfinder", "-dL", "targets.txt"],
        exit_code=0,
        stdout=mock_ndjson,
        stderr="",
        duration_seconds=1.5,
        started_at="2026-08-20T00:00:00Z",
        finished_at="2026-08-20T00:00:01Z",
        tool_result_id=999,
    )

    with patch("reconw.stages.subfinder.run_tool", return_value=mock_result):
        discovered = run_subfinder(
            in_scope_domains=in_scope,
            run_id=run_id,
            scope_evaluator=evaluator,
        )

    # blog.example.com is out-of-scope, so only api.example.com and dev.example.com should be returned
    assert len(discovered) == 2
    assert "api.example.com" in discovered
    assert "dev.example.com" in discovered
    assert "blog.example.com" not in discovered

    # Verify assets were saved to the SQLite database
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT hostname, root_domain, first_seen_run_id, source_tool_result_id FROM asset ORDER BY hostname")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0] == ("api.example.com", "example.com", run_id, 999)
    assert rows[1] == ("dev.example.com", "example.com", run_id, 999)

import json
import sqlite3
from pathlib import Path
import pytest
from typer.testing import CliRunner

from reconw.cli import cli
from reconw.report.generator import generate_report_data, render_html_report
from reconw.storage.db import init_db
from reconw.storage.repository import (
    create_run,
    create_tool_result,
    insert_endpoint,
    insert_score,
    upsert_asset,
)

runner = CliRunner()


def test_generate_report_data_and_render(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_report.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="COMPLETED", cli_args="reconw run -i scope.txt")

    # 1. Add Tool Result
    tool_res_id = create_tool_result(
        run_id=run_id,
        stage_name="subdomain_enum",
        tool_name="subfinder",
        command="subfinder -d example.com",
        exit_code=0,
        item_count=1,
    )

    # 2. Add Asset
    asset_id = upsert_asset(
        canonical_key="api.example.com",
        hostname="api.example.com",
        root_domain="example.com",
        run_id=run_id,
        tool_result_id=tool_res_id,
    )

    # 3. Add Endpoint
    ep_id = insert_endpoint(
        run_id=run_id,
        asset_id=asset_id,
        url="https://api.example.com/admin/login",
        dedup_key="key123",
        status_code=200,
        content_length=1500,
        title="Admin Portal",
        tech_stack_json='["WordPress", "Nginx"]',
        screenshot_path="./screenshots/admin.png",
        source_tool_result_id=tool_res_id,
    )

    # 4. Add Score
    insert_score(
        run_id=run_id,
        endpoint_id=ep_id,
        score=75,
        band="Critical",
        score_breakdown_json=json.dumps({"admin_keyword": 30, "live_200": 10, "tech": 15, "path": 20}),
    )

    # Test Data Assembly
    data = generate_report_data(run_id)
    assert data["run"]["id"] == run_id
    assert len(data["assets"]) == 1
    assert len(data["endpoints"]) == 1
    assert len(data["scores"]) == 1
    assert data["critical_count"] == 1
    assert "WordPress" in data["tech_distribution"]

    # Test HTML File Rendering
    report_file = tmp_path / "custom_report.html"
    out_path = render_html_report(run_id=run_id, output_path=report_file)
    assert out_path.exists()

    html_content = out_path.read_text(encoding="utf-8")
    assert f"Run #{run_id}" in html_content
    assert "api.example.com" in html_content
    assert "Critical" in html_content
    assert "WordPress" in html_content
    assert "reportDataBlob" in html_content


def test_cli_report_command(tmp_path: Path):
    db_file = tmp_path / "test_cli_report.db"
    init_db(db_file)

    run_id = create_run(status="COMPLETED")
    out_file = tmp_path / "cli_report.html"

    res = runner.invoke(cli, ["report", "-r", str(run_id), "-o", str(out_file), "-d", str(db_file)])
    assert res.exit_code == 0
    assert "Report generated successfully" in res.stdout
    assert out_file.exists()

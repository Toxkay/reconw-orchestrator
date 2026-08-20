import json
import sqlite3
from pathlib import Path
import pytest

from reconw.stages.prioritize import (
    calculate_endpoint_score,
    run_prioritize,
)
from reconw.storage.db import init_db
from reconw.storage.repository import create_run, insert_endpoint


def test_calculate_endpoint_score_critical_admin():
    endpoint_data = {
        "id": 1,
        "url": "https://api.example.com/admin/login",
        "title": "Admin Dashboard Portal",
        "status_code": 200,
        "content_length": 2500,
        "tech_stack_json": '["WordPress", "PHP"]',
    }

    scored = calculate_endpoint_score(endpoint_data)
    assert scored.score >= 70
    assert scored.band == "Critical"
    assert any("admin_keyword" in k for k in scored.breakdown)
    assert any("sensitive_path" in k for k in scored.breakdown)
    assert any("notable_tech" in k for k in scored.breakdown)
    assert scored.breakdown.get("live_200_response") == 10


def test_calculate_endpoint_score_protected_resource():
    endpoint_data = {
        "id": 2,
        "url": "https://example.com/internal/metrics",
        "title": "Unauthorized",
        "status_code": 403,
        "content_length": 150,
        "tech_stack_json": "[]",
    }

    scored = calculate_endpoint_score(endpoint_data)
    assert scored.score == 30  # sensitive_path (20) + protected_status (10)
    assert scored.band == "Medium"
    assert any("protected_status" in k for k in scored.breakdown)


def test_calculate_endpoint_score_parked_page():
    endpoint_data = {
        "id": 3,
        "url": "http://old.example.com",
        "title": "Parked Domain - Under Construction",
        "status_code": 200,
        "content_length": 0,
        "tech_stack_json": "[]",
    }

    scored = calculate_endpoint_score(endpoint_data)
    assert scored.score == 0
    assert scored.band == "Info"
    assert scored.breakdown.get("empty_or_parking_page") == -10


def test_run_prioritize_stage_db_integration(tmp_path: Path, monkeypatch):
    db_file = tmp_path / "test_prioritize.db"
    init_db(db_file)
    monkeypatch.setattr("reconw.storage.db.DB_PATH", db_file)

    run_id = create_run(status="RUNNING")

    # Insert two sample endpoints
    ep1_id = insert_endpoint(
        run_id=run_id,
        asset_id=10,
        url="https://api.example.com/admin/login",
        dedup_key="key1",
        status_code=200,
        content_length=1500,
        title="Admin Portal",
        tech_stack_json='["WordPress"]',
    )
    ep2_id = insert_endpoint(
        run_id=run_id,
        asset_id=10,
        url="https://example.com/about",
        dedup_key="key2",
        status_code=200,
        content_length=500,
        title="About Us",
        tech_stack_json='[]',
    )

    scored_list = run_prioritize(run_id=run_id)
    assert len(scored_list) == 2
    assert scored_list[0].endpoint_id == ep1_id
    assert scored_list[0].score > scored_list[1].score

    # Verify score rows in SQLite
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT endpoint_id, score, band, rules_version FROM score ORDER BY score DESC")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 2
    assert rows[0][0] == ep1_id
    assert rows[0][1] >= 70
    assert rows[0][2] == "Critical"
    assert rows[0][3] == "v1.0"

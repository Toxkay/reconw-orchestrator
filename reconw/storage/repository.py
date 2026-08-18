import sqlite3
from datetime import datetime, timezone
from typing import Optional
from reconw.storage.db import get_connection

def utc_now() -> str:
    """Returns current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()

# ==========================================
# 1. Pipeline Run Lifecycle
# ==========================================

def create_run(status: str = "RUNNING", scope_file_hash: str = "", config_hash: str = "", cli_args: str = "") -> int:
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO run (started_at, status, scope_file_hash, config_hash, cli_args) VALUES (?, ?, ?, ?, ?)",
        (utc_now(), status, scope_file_hash, config_hash, cli_args)
    )
    conn.commit()
    return cursor.lastrowid

def finish_run(run_id: int, status: str = "COMPLETED") -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE run SET finished_at = ?, status = ? WHERE id = ?",
        (utc_now(), status, run_id)
    )
    conn.commit()

# ==========================================
# 2. Tool Execution Provenance
# ==========================================

def create_tool_result(
    run_id: int,
    stage_name: str,
    tool_name: str,
    command: str,
    exit_code: int,
    tool_version: str = "",
    started_at: str = "",
    finished_at: str = "",
    raw_output_path: str = "",
    item_count: int = 0,
    error_message: str = ""
) -> int:
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO tool_result (
            run_id, stage_name, tool_name, tool_version, command,
            exit_code, started_at, finished_at, raw_output_path, item_count, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, stage_name, tool_name, tool_version, command, exit_code,
         started_at or utc_now(), finished_at or utc_now(), raw_output_path, item_count, error_message)
    )
    conn.commit()
    return cursor.lastrowid

# ==========================================
# 3. Assets (Subfinder -> DB -> Next Tool)
# ==========================================

def upsert_asset(canonical_key: str, hostname: str, root_domain: str, run_id: int, tool_result_id: Optional[int] = None) -> int:
    """Inserts a new asset or returns existing asset ID if already discovered."""
    conn = get_connection()
    # Insert or ignore duplicate canonical_keys
    conn.execute(
        """
        INSERT INTO asset (canonical_key, hostname, root_domain, first_seen_run_id, source_tool_result_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(canonical_key) DO NOTHING
        """,
        (canonical_key, hostname, root_domain, run_id, tool_result_id, utc_now())
    )
    conn.commit()
    
    # Retrieve asset id
    cursor = conn.execute("SELECT id FROM asset WHERE canonical_key = ?", (canonical_key,))
    row = cursor.fetchone()
    return row[0] if row else 0

def get_assets_for_run(run_id: int) -> list[dict]:
    """Fetch all assets discovered during a run to feed into DNSx or HTTPx."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT id, canonical_key, hostname, root_domain FROM asset WHERE first_seen_run_id = ?",
        (run_id,)
    )
    return [dict(row) for row in cursor.fetchall()]

# ==========================================
# 4. DNS Records (DNSx -> DB -> Next Tool)
# ==========================================

def insert_dns_record(asset_id: int, record_type: str, value: str, source_tool_result_id: int) -> int:
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO dns_record (asset_id, record_type, value, resolved_at, source_tool_result_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (asset_id, record_type, value, utc_now(), source_tool_result_id)
    )
    conn.commit()
    return cursor.lastrowid

# ==========================================
# 5. Endpoints (HTTPx -> DB -> Katana)
# ==========================================

def insert_endpoint(
    run_id: int,
    asset_id: int,
    url: str,
    dedup_key: str,
    status_code: int,
    content_length: int,
    title: str = "",
    tech_stack_json: str = "[]",
    screenshot_path: str = "",
    source_tool_result_id: Optional[int] = None
) -> int:
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO endpoint (
            run_id, asset_id, url, dedup_key, status_code, content_length,
            title, tech_stack_json, screenshot_path, source_tool_result_id, captured_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, dedup_key) DO UPDATE SET
            status_code=excluded.status_code,
            content_length=excluded.content_length,
            tech_stack_json=excluded.tech_stack_json
        """,
        (run_id, asset_id, url, dedup_key, status_code, content_length,
         title, tech_stack_json, screenshot_path, source_tool_result_id, utc_now())
    )
    conn.commit()
    return cursor.lastrowid

def get_live_endpoints_for_run(run_id: int) -> list[dict]:
    """Fetch live HTTP endpoints to pass to katana / crawler."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT id, url, asset_id FROM endpoint WHERE run_id = ? AND status_code < 400",
        (run_id,)
    )
    return [dict(row) for row in cursor.fetchall()]

# ==========================================
# 6. Crawled URLs (Katana -> DB)
# ==========================================

def insert_url_item(run_id: int, endpoint_id: int, url: str, dedup_key: str, source_tool_result_id: int) -> int:
    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO url_item (run_id, endpoint_id, url, dedup_key, source_tool_result_id, discovered_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (run_id, endpoint_id, url, dedup_key, source_tool_result_id, utc_now())
    )
    conn.commit()
    return cursor.lastrowid

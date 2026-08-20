CREATE TABLE IF NOT EXISTS run (
  id INTEGER PRIMARY KEY,
  program_name TEXT,
  started_at TEXT, finished_at TEXT, status TEXT,
  scope_file_hash TEXT, config_hash TEXT, cli_args TEXT
);

CREATE TABLE IF NOT EXISTS tool_result (
  id INTEGER PRIMARY KEY, run_id INTEGER, stage_name TEXT,
  tool_name TEXT, tool_version TEXT, command TEXT,
  exit_code INTEGER, started_at TEXT, finished_at TEXT,
  raw_output_path TEXT, item_count INTEGER, error_message TEXT
);

CREATE TABLE IF NOT EXISTS asset (
  id INTEGER PRIMARY KEY, canonical_key TEXT UNIQUE,
  hostname TEXT, root_domain TEXT,
  first_seen_run_id INTEGER, source_tool_result_id INTEGER, created_at TEXT
);

CREATE TABLE IF NOT EXISTS dns_record (
  id INTEGER PRIMARY KEY, asset_id INTEGER, record_type TEXT,
  value TEXT, resolved_at TEXT, source_tool_result_id INTEGER
);

CREATE TABLE IF NOT EXISTS endpoint (
  id INTEGER PRIMARY KEY, run_id INTEGER, asset_id INTEGER,
  url TEXT, dedup_key TEXT, status_code INTEGER, content_length INTEGER,
  title TEXT, tech_stack_json TEXT, screenshot_path TEXT,
  source_tool_result_id INTEGER, captured_at TEXT,
  UNIQUE(asset_id, dedup_key)
);

CREATE TABLE IF NOT EXISTS url_item (
  id INTEGER PRIMARY KEY, run_id INTEGER, endpoint_id INTEGER,
  url TEXT, dedup_key TEXT, source_tool_result_id INTEGER, discovered_at TEXT
);

CREATE TABLE IF NOT EXISTS score (
  id INTEGER PRIMARY KEY, run_id INTEGER, endpoint_id INTEGER,
  score INTEGER, band TEXT, score_breakdown_json TEXT,
  rules_version TEXT, computed_at TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY, related_table TEXT, related_id INTEGER,
  evidence_type TEXT, file_path TEXT, sha256 TEXT, created_at TEXT
);

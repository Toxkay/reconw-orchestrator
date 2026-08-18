-- one row per pipeline execution
CREATE TABLE run (
  id INTEGER PRIMARY KEY,
  started_at TEXT, finished_at TEXT, status TEXT,
  scope_file_hash TEXT, config_hash TEXT, cli_args TEXT
);

-- one row per external tool invocation — THE provenance table
CREATE TABLE tool_result (
  id INTEGER PRIMARY KEY, run_id INTEGER, stage_name TEXT,
  tool_name TEXT, tool_version TEXT, command TEXT,
  exit_code INTEGER, started_at TEXT, finished_at TEXT,
  raw_output_path TEXT, item_count INTEGER, error_message TEXT
);

-- discovered subdomains; canonical_key is globally unique so first_seen_run_id works
CREATE TABLE asset (
  id INTEGER PRIMARY KEY, canonical_key TEXT UNIQUE,
  hostname TEXT, root_domain TEXT,
  first_seen_run_id INTEGER, source_tool_result_id INTEGER, created_at TEXT
);

CREATE TABLE dns_record (
  id INTEGER PRIMARY KEY, asset_id INTEGER, record_type TEXT,
  value TEXT, resolved_at TEXT, source_tool_result_id INTEGER
);

-- live HTTP(S) endpoints from httpx
CREATE TABLE endpoint (
  id INTEGER PRIMARY KEY, run_id INTEGER, asset_id INTEGER,
  url TEXT, dedup_key TEXT, status_code INTEGER, content_length INTEGER,
  title TEXT, tech_stack_json TEXT, screenshot_path TEXT,
  source_tool_result_id INTEGER, captured_at TEXT,
  UNIQUE(asset_id, dedup_key)
);

-- crawled URLs/endpoints from katana
CREATE TABLE url_item (
  id INTEGER PRIMARY KEY, run_id INTEGER, endpoint_id INTEGER,
  url TEXT, dedup_key TEXT, source_tool_result_id INTEGER, discovered_at TEXT
);

CREATE TABLE score (
  id INTEGER PRIMARY KEY, run_id INTEGER, endpoint_id INTEGER,
  score INTEGER, band TEXT, score_breakdown_json TEXT,
  rules_version TEXT, computed_at TEXT
);

-- generic attachment table: screenshots, header dumps, response snippets
CREATE TABLE evidence (
  id INTEGER PRIMARY KEY, related_table TEXT, related_id INTEGER,
  evidence_type TEXT, file_path TEXT, sha256 TEXT, created_at TEXT
);
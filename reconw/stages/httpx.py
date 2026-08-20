"""Stage 3: HTTP Probing, Tech Detection & Screenshots using httpx.

Probes live web servers on resolved hosts, detects technologies,
captures status codes/titles, and persists endpoints into SQLite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from reconw.scope.validator import ScopeEvaluator
from reconw.storage.repository import insert_endpoint, upsert_asset
from reconw.tools.parser import HttpxEndpoint, parse_httpx_output
from reconw.tools.runner import run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_hostname


def extract_targets(targets: Sequence[str]) -> list[str]:
    """Extracts clean unique hostnames or URLs for HTTP probing."""
    cleaned: set[str] = set()
    for t in targets:
        clean = t.strip()
        if not clean:
            continue
        if clean.startswith("*."):
            clean = clean[2:]
        canonical, _, _ = canonicalize_hostname(clean)
        if canonical:
            cleaned.add(canonical)
    return sorted(cleaned)


def run_httpx(
    targets: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    screenshots_dir: Path | str = Path("screenshots"),
    timeout: int = 600,
    retries: int = 1,
) -> list[str]:
    """Executes the HTTPX probing stage.

    Args:
        targets: Resolved live hostnames from Stage 2 (DNSx).
        run_id: Current pipeline run identifier.
        scope_evaluator: Optional evaluator to enforce scope rules.
        screenshots_dir: Directory where screenshots will be stored.
        timeout: Execution timeout in seconds.
        retries: Number of retry attempts on failure.

    Returns:
        List of live, reachable HTTP(S) URLs.
    """
    clean_targets = extract_targets(targets)
    if not clean_targets:
        return []

    # Ensure screenshots folder exists
    srd_path = Path(screenshots_dir)
    srd_path.mkdir(parents=True, exist_ok=True)

    temp_targets_file = write_temp_targets(clean_targets, prefix="recon_httpx_")

    base_args = [
        "-l", str(temp_targets_file),
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-content-length",
    ]

    try:
        # First attempt with screenshots
        screenshot_args = base_args + ["-screenshot", "-srd", str(srd_path)]
        result = run_tool(
            tool_name="httpx",
            args=screenshot_args,
            stage_name="http_probe",
            run_id=run_id,
            timeout=timeout,
            retries=retries,
        )

        # If httpx failed (e.g. chromium missing on Linux), retry without -screenshot
        if not result.stdout and result.exit_code != 0:
            result = run_tool(
                tool_name="httpx",
                args=base_args,
                stage_name="http_probe",
                run_id=run_id,
                timeout=timeout,
                retries=retries,
            )

    finally:
        temp_targets_file.unlink(missing_ok=True)

    # Parse stdout/raw NDJSON output into HttpxEndpoint objects
    endpoints: list[HttpxEndpoint] = parse_httpx_output(result.stdout)

    live_urls: list[str] = []
    seen: set[str] = set()

    for item in endpoints:
        url = item.url
        if url in seen:
            continue

        # Enforce scope guardrails
        if scope_evaluator and not scope_evaluator.is_in_scope(item.hostname):
            continue

        seen.add(url)
        live_urls.append(url)

        # Get or create the parent asset ID in the database
        _, root_domain, canonical_key = canonicalize_hostname(item.hostname)
        asset_id = upsert_asset(
            canonical_key=canonical_key,
            hostname=item.hostname,
            root_domain=root_domain,
            run_id=run_id,
            tool_result_id=result.tool_result_id,
        )

        # Persist endpoint record in SQLite
        insert_endpoint(
            run_id=run_id,
            asset_id=asset_id,
            url=item.url,
            dedup_key=item.dedup_key,
            status_code=item.status_code,
            content_length=item.content_length,
            title=item.title,
            tech_stack_json=json.dumps(item.tech_stack),
            screenshot_path=item.screenshot_path,
            source_tool_result_id=result.tool_result_id,
        )

    return live_urls

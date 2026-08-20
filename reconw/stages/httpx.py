"""Stage 3: HTTP Probing, Tech Detection & Screenshots using httpx.

Probes live web servers on resolved hosts, detects technologies,
captures status codes/titles, and persists endpoints into SQLite.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Sequence

from rich.console import Console

from reconw.scope.validator import ScopeEvaluator
from reconw.storage.repository import insert_endpoint, upsert_asset
from reconw.tools.parser import HttpxEndpoint, parse_httpx_output
from reconw.tools.runner import resolve_tool_binary, run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_hostname

console = Console(highlight=False)


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
    clean_targets = extract_targets(targets)
    if not clean_targets:
        console.print("[dim][DEBUG httpx][/dim] No targets provided for HTTP probing.")
        return []

    binary_path = resolve_tool_binary("httpx")
    console.print(f"[dim][DEBUG httpx][/dim] Binary resolved: [cyan]{binary_path}[/cyan]")
    console.print(f"[dim][DEBUG httpx][/dim] Probing targets count: {len(clean_targets)} hosts (e.g. {', '.join(clean_targets[:5])})")

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
        console.print(f"[dim][DEBUG httpx][/dim] Running command: `{' '.join([str(binary_path)] + base_args)}`")
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

    console.print(f"[dim][DEBUG httpx][/dim] Exit code: {result.exit_code}, Output length: {len(result.stdout)} bytes, Stderr length: {len(result.stderr)} bytes")
    if result.stderr:
        console.print(f"[bold red][DEBUG httpx stderr][/bold red] {result.stderr.strip()[:400]}")

    if result.stdout:
        console.print(f"[dim][DEBUG httpx sample stdout][/dim] {result.stdout.strip().splitlines()[0][:200]}")
    else:
        console.print("[dim][DEBUG httpx][/dim] Warning: HTTPx stdout was empty.")

    # Parse stdout/raw NDJSON output into HttpxEndpoint objects
    endpoints: list[HttpxEndpoint] = parse_httpx_output(result.stdout)
    console.print(f"[dim][DEBUG httpx][/dim] Parsed {len(endpoints)} endpoint objects from output")

    live_urls: list[str] = []
    seen: set[str] = set()
    filtered_out = 0

    for item in endpoints:
        url = item.url
        if url in seen:
            continue

        # Enforce scope guardrails
        if scope_evaluator and not scope_evaluator.is_in_scope(item.hostname):
            filtered_out += 1
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

    if filtered_out > 0:
        console.print(f"[dim][DEBUG httpx][/dim] {filtered_out} endpoints were filtered out by scope.")

    return live_urls

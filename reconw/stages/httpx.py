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

    # DEBUG DUMP 1: Input file
    try:
        Path("debug_httpx_input.txt").write_text("\n".join(clean_targets) + "\n", encoding="utf-8")
        console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved HTTPx input targets to [bold green]debug_httpx_input.txt[/bold green] ({len(clean_targets)} hosts)")
    except Exception:
        pass

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

    # DEBUG DUMP 2: Raw output file
    try:
        Path("debug_httpx_raw_output.txt").write_text(result.stdout, encoding="utf-8")
        console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved HTTPx raw output to [bold green]debug_httpx_raw_output.txt[/bold green] ({len(result.stdout)} bytes)")
    except Exception:
        pass

    console.print(f"[dim][DEBUG httpx][/dim] Exit code: {result.exit_code}, Output length: {len(result.stdout)} bytes, Stderr length: {len(result.stderr)} bytes")
    if result.stderr:
        console.print(f"[bold red][DEBUG httpx stderr][/bold red] {result.stderr.strip()[:400]}")

    # Parse stdout/raw NDJSON output into HttpxEndpoint objects
    endpoints: list[HttpxEndpoint] = parse_httpx_output(result.stdout)
    console.print(f"[dim][DEBUG httpx][/dim] Parsed {len(endpoints)} endpoint objects from output")

    live_urls: list[str] = []
    seen: set[str] = set()

    for ep in endpoints:
        url = ep.url
        if not url or url in seen:
            continue

        # Enforce scope guardrails on HTTP endpoints
        hostname = ep.hostname
        if scope_evaluator and hostname and not scope_evaluator.is_in_scope(hostname):
            continue

        seen.add(url)
        live_urls.append(url)

        # Upsert parent asset in SQLite
        asset_id = 0
        if hostname:
            _, root_domain, canonical_key = canonicalize_hostname(hostname)
            asset_id = upsert_asset(
                canonical_key=canonical_key,
                hostname=hostname,
                root_domain=root_domain,
                run_id=run_id,
                tool_result_id=result.tool_result_id,
            )

        # Record HTTP endpoint into SQLite table
        insert_endpoint(
            run_id=run_id,
            asset_id=asset_id,
            url=ep.url,
            dedup_key=ep.dedup_key,
            status_code=ep.status_code,
            content_length=ep.content_length,
            title=ep.title,
            tech_stack_json=json.dumps(ep.tech_stack),
            screenshot_path="",
            source_tool_result_id=result.tool_result_id,
        )

    # DEBUG DUMP 3: Filtered output file
    try:
        Path("debug_httpx_filtered_output.txt").write_text("\n".join(live_urls) + "\n", encoding="utf-8")
        console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved HTTPx filtered output to [bold green]debug_httpx_filtered_output.txt[/bold green] ({len(live_urls)} endpoints)")
    except Exception:
        pass

    return live_urls

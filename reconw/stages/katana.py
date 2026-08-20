"""Stage 4: URL & Endpoint Collection using Katana.

Performs shallow active crawling against live web applications to discover
hidden API routes, JavaScript files, forms, and parameterized endpoints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

from rich.console import Console

from reconw.scope.validator import ScopeEvaluator
from reconw.storage.repository import insert_url_item
from reconw.tools.parser import KatanaUrlItem, parse_katana_output
from reconw.tools.runner import resolve_tool_binary, run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_url

console = Console(highlight=False)


def clean_seed_urls(urls: Sequence[str]) -> list[str]:
    """Cleans and validates seed URLs for crawling."""
    cleaned: set[str] = set()
    for u in urls:
        raw = u.strip()
        if not raw:
            continue
        normalized, _ = canonicalize_url(raw)
        if normalized:
            cleaned.add(normalized)
    return sorted(cleaned)


def run_katana(
    seed_urls: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    depth: int = 2,
    rate_limit: int = 10,
    timeout: int = 600,
    retries: int = 0,
) -> list[str]:
    clean_seeds = clean_seed_urls(seed_urls)
    if not clean_seeds:
        console.print("[dim][DEBUG katana][/dim] No seed URLs provided for crawling.")
        return []

    binary_path = resolve_tool_binary("katana")
    console.print(f"[dim][DEBUG katana][/dim] Binary resolved: [cyan]{binary_path}[/cyan]")
    console.print(f"[dim][DEBUG katana][/dim] Seed URLs count: {len(clean_seeds)} (e.g. {', '.join(clean_seeds[:3])})")

    temp_seeds_file = write_temp_targets(clean_seeds, prefix="recon_katana_")

    args = [
        "-u", str(temp_seeds_file),
        "-silent",
        "-j",
        "-d", str(depth),
        "-rl", str(rate_limit),
        "-jc",
    ]

    try:
        console.print(f"[dim][DEBUG katana][/dim] Running command: `{' '.join([str(binary_path)] + args)}`")
        result = run_tool(
            tool_name="katana",
            args=args,
            stage_name="url_collect",
            run_id=run_id,
            timeout=timeout,
            retries=retries,
        )
    finally:
        temp_seeds_file.unlink(missing_ok=True)

    console.print(f"[dim][DEBUG katana][/dim] Exit code: {result.exit_code}, Output length: {len(result.stdout)} bytes")
    if result.stderr and result.exit_code != 0:
        console.print(f"[bold red][DEBUG katana stderr][/bold red] {result.stderr.strip()[:300]}")

    # Parse stdout/raw NDJSON output into KatanaUrlItem objects
    crawled_items: list[KatanaUrlItem] = parse_katana_output(result.stdout)
    console.print(f"[dim][DEBUG katana][/dim] Parsed {len(crawled_items)} crawled items from output")

    discovered_urls: list[str] = []
    seen: set[str] = set()

    for item in crawled_items:
        url = item.url
        if url in seen:
            continue

        # Extract hostname to verify against scope
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if scope_evaluator and not scope_evaluator.is_in_scope(hostname):
            continue

        seen.add(url)
        discovered_urls.append(url)

        # Persist crawled URL into url_item table
        insert_url_item(
            run_id=run_id,
            endpoint_id=0,
            url=item.url,
            dedup_key=item.dedup_key,
            source_tool_result_id=result.tool_result_id or 0,
        )

    return discovered_urls
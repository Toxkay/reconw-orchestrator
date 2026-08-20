"""Stage 4: URL & Endpoint Collection using Katana.

Performs shallow active crawling against live web applications to discover
hidden API routes, JavaScript files, forms, and parameterized endpoints.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence
from urllib.parse import urlparse

from reconw.scope.validator import ScopeEvaluator
from reconw.storage.repository import insert_url_item
from reconw.tools.parser import KatanaUrlItem, parse_katana_output
from reconw.tools.runner import run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_url


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
    """Executes the Katana crawler stage.

    Args:
        seed_urls: Live HTTP(S) endpoint URLs from Stage 3 (HTTPx).
        run_id: Current pipeline run identifier.
        scope_evaluator: Optional evaluator to enforce scope boundaries.
        depth: Crawl depth limit (default: 2).
        rate_limit: Maximum requests per second (default: 10).
        timeout: Subprocess execution timeout in seconds.
        retries: Number of retry attempts on failure.

    Returns:
        List of unique, discovered endpoint URLs.
    """
    clean_seeds = clean_seed_urls(seed_urls)
    if not clean_seeds:
        return []

    temp_seeds_file = write_temp_targets(clean_seeds, prefix="recon_katana_")

    args = [
        "-u", str(temp_seeds_file),
        "-silent",
        "-j",
        "-d", str(depth),
        "-rl", str(rate_limit),
        "-jc",  # JavaScript crawl support
    ]

    try:
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

    # Parse stdout/raw NDJSON output into KatanaUrlItem objects
    crawled_items: list[KatanaUrlItem] = parse_katana_output(result.stdout)

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
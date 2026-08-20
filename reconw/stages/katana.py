"""Stage 4: Active Web Crawling using Katana.

Crawls live web services discovered by HTTPx, extracts JavaScript API routes,
endpoints, and URLs, enforces scope guardrails, and records items into SQLite.
"""

from __future__ import annotations

import tempfile
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
    """Ensures seed URLs have valid HTTP/HTTPS schemes."""
    cleaned: set[str] = set()
    for u in urls:
        raw = u.strip()
        if not raw:
            continue
        if not raw.startswith(("http://", "https://")):
            raw = f"http://{raw}"
        cleaned.add(raw)
    return sorted(cleaned)


def run_katana(
    seed_urls: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    depth: int = 2,
    rate_limit: int = 150,
    concurrency: int = 30,
    crawl_duration_minutes: int = 1,
    timeout: int = 1200,
    retries: int = 0,
) -> list[str]:
    clean_seeds = clean_seed_urls(seed_urls)
    if not clean_seeds:
        console.print("[dim][DEBUG katana][/dim] No seed URLs provided for crawling.")
        return []

    binary_path = resolve_tool_binary("katana")
    console.print(f"[dim][DEBUG katana][/dim] Binary resolved: [cyan]{binary_path}[/cyan]")
    console.print(f"[dim][DEBUG katana][/dim] Seed URLs count: {len(clean_seeds)} (e.g. {', '.join(clean_seeds[:3])})")

    temp_seeds_file = write_temp_targets(clean_seeds, prefix="recon_katana_seeds_")

    # Create temporary output file so Katana streams output to disk continuously
    temp_out = tempfile.NamedTemporaryFile(prefix="recon_katana_out_", suffix=".jsonl", delete=False)
    temp_out_path = Path(temp_out.name)
    temp_out.close()

    # Calculate dynamic stage timeout scaled for mass target lists (minimum 20 minutes)
    effective_timeout = max(timeout, min(3600, len(clean_seeds) * 2))

    # Katana flags optimized for high-performance & resilience on mass target lists:
    # -u / -list: Target seed URLs file
    # -o: File output to stream results to disk continuously (prevents loss on timeout)
    # -j / -jsonl: JSON Lines output
    # -jc: Enable JavaScript endpoint crawling
    # -ct 1m: Max crawl duration per target (1 minute cap per target)
    # -or / -ob: Omit raw requests/responses & body to keep RAM tiny (<5MB vs 800MB)
    args = [
        "-u", str(temp_seeds_file),
        "-o", str(temp_out_path),
        "-silent",
        "-j",
        "-d", str(depth),
        "-c", str(concurrency),
        "-rl", str(rate_limit),
        "-ct", f"{crawl_duration_minutes}m",
        "-jc",
        "-or",
        "-ob",
    ]

    try:
        console.print(f"[dim][DEBUG katana][/dim] Running command: `{' '.join([str(binary_path)] + args)}` (timeout={effective_timeout}s)")
        result = run_tool(
            tool_name="katana",
            args=args,
            stage_name="url_collect",
            run_id=run_id,
            timeout=effective_timeout,
            retries=retries,
            raw_output_path=temp_out_path,
        )
    finally:
        temp_seeds_file.unlink(missing_ok=True)

    # Read output from temp output file or stdout (preserves crawled items even if timed out)
    raw_output = ""
    if temp_out_path.exists():
        try:
            raw_output = temp_out_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
        temp_out_path.unlink(missing_ok=True)

    if not raw_output and result.stdout:
        raw_output = result.stdout

    console.print(f"[dim][DEBUG katana][/dim] Exit code: {result.exit_code}, Disk output length: {len(raw_output)} bytes")
    if result.stderr and result.exit_code not in (0, 124):
        console.print(f"[bold red][DEBUG katana stderr][/bold red] {result.stderr.strip()[:300]}")

    # Parse stdout/raw NDJSON output into KatanaUrlItem objects
    crawled_items: list[KatanaUrlItem] = parse_katana_output(raw_output)
    console.print(f"[dim][DEBUG katana][/dim] Parsed {len(crawled_items)} crawled items from output")

    discovered_urls: list[str] = []
    seen: set[str] = set()

    for item in crawled_items:
        url = item.url
        if url in seen:
            continue

        # Extract hostname safely without throwing on malformed IPv6 URLs
        hostname = ""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            clean_host = url.split("://")[-1].split("/")[0].split("?")[0].split(":")[0].strip("[]")
            hostname = clean_host

        if scope_evaluator and hostname and not scope_evaluator.is_in_scope(hostname):
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
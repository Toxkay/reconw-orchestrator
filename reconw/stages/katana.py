"""Stage 4: Active Web Crawling using Katana.

Crawls live web services discovered by HTTPx, extracts JavaScript API routes,
endpoints, and URLs, enforces scope guardrails, and records items into SQLite.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from enum import Enum
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


class CrawlMode(str, Enum):
    FAST = "fast"
    DEEP = "deep"


@dataclass(frozen=True)
class KatanaModeConfig:
    depth: int
    rate_limit: int
    concurrency: int
    crawl_duration_minutes: int
    enable_js_crawling: bool
    omit_raw_request_body: bool = True
    omit_raw_response_body: bool = True


FAST_MODE = KatanaModeConfig(
    depth=1,
    rate_limit=200,
    concurrency=25,
    crawl_duration_minutes=0,
    enable_js_crawling=False,
)

DEEP_MODE = KatanaModeConfig(
    depth=2,
    rate_limit=300,
    concurrency=50,
    crawl_duration_minutes=2,
    enable_js_crawling=True,
)


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


def get_katana_mode_config(mode: CrawlMode) -> KatanaModeConfig:
    if mode == CrawlMode.DEEP:
        return DEEP_MODE
    return FAST_MODE


def run_katana(
    seed_urls: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    depth: int | None = None,
    rate_limit: int | None = None,
    concurrency: int | None = None,
    crawl_duration_minutes: int | None = None,
    timeout: int = 600,
    retries: int = 0,
    mode: CrawlMode = CrawlMode.FAST,
    enable_js_crawling: bool | None = None,
) -> list[str]:
    clean_seeds = clean_seed_urls(seed_urls)
    if not clean_seeds:
        console.print("[dim][DEBUG katana][/dim] No seed URLs provided for crawling.")
        return []

    binary_path = resolve_tool_binary("katana")
    console.print(f"[dim][DEBUG katana][/dim] Binary resolved: [cyan]{binary_path}[/cyan]")
    console.print(f"[dim][DEBUG katana][/dim] Seed URLs count: {len(clean_seeds)} (e.g. {', '.join(clean_seeds[:3])})")

    config = get_katana_mode_config(mode)

    effective_depth = depth if depth is not None else config.depth
    effective_rate_limit = rate_limit if rate_limit is not None else config.rate_limit
    effective_concurrency = concurrency if concurrency is not None else config.concurrency
    effective_crawl_duration_minutes = (
        crawl_duration_minutes if crawl_duration_minutes is not None else config.crawl_duration_minutes
    )
    effective_js = enable_js_crawling if enable_js_crawling is not None else config.enable_js_crawling

    temp_seeds_file = write_temp_targets(clean_seeds, prefix="recon_katana_seeds_")

    temp_out = tempfile.NamedTemporaryFile(prefix="recon_katana_out_", suffix=".jsonl", delete=False)
    temp_out_path = Path(temp_out.name)
    temp_out.close()

    # Keep fast mode tightly bounded; deep mode can be a bit longer.
    if mode == CrawlMode.FAST:
        effective_timeout = min(timeout, 300)
    else:
        effective_timeout = max(timeout, min(1800, len(clean_seeds) * 2))

    args = [
        "-u", str(temp_seeds_file),
        "-o", str(temp_out_path),
        "-silent",
        "-j",
        "-d", str(effective_depth),
        "-c", str(effective_concurrency),
        "-rl", str(effective_rate_limit),
        "-or",
        "-ob",
    ]

    if effective_crawl_duration_minutes > 0:
        args.extend(["-ct", f"{effective_crawl_duration_minutes}m"])

    if effective_js:
        args.append("-jc")

    try:
        console.print(
            f"[dim][DEBUG katana][/dim] Running command: `{' '.join([str(binary_path)] + args)}` "
            f"(timeout={effective_timeout}s)"
        )
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

    crawled_items: list[KatanaUrlItem] = parse_katana_output(raw_output)
    console.print(f"[dim][DEBUG katana][/dim] Parsed {len(crawled_items)} crawled items from output")

    discovered_urls: list[str] = []
    seen: set[str] = set()

    for item in crawled_items:
        url_normalized, _ = canonicalize_url(item.url)
        url = url_normalized if url_normalized else item.url
        if url in seen:
            continue

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

        insert_url_item(
            run_id=run_id,
            endpoint_id=0,
            url=url,
            dedup_key=item.dedup_key,
            source_tool_result_id=result.tool_result_id or 0,
        )

    return discovered_urls
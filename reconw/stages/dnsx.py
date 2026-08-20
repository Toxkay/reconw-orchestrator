"""Stage 2: DNS Resolution using DNSx.

Resolves discovered subdomains, records A/AAAA/CNAME entries into SQLite,
and filters out non-resolving or dead hosts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from rich.console import Console

from reconw.scope.validator import DomainValidator, ScopeEvaluator
from reconw.storage.repository import insert_dns_record, upsert_asset
from reconw.tools.parser import DnsxResult, parse_dnsx_output
from reconw.tools.runner import run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_hostname

console = Console(highlight=False)


def extract_hostnames(domains: Sequence[str]) -> list[str]:
    """Extracts clean unique hostnames from in-scope targets."""
    hostnames: set[str] = set()
    for d in domains:
        clean = d.strip()
        if not clean:
            continue
        if clean.startswith("*."):
            clean = clean[2:]
        canonical, _, _ = canonicalize_hostname(clean)
        if canonical:
            hostnames.add(canonical)
    return sorted(hostnames)


def run_dnsx(
    hostnames: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    timeout: int = 300,
    retries: int = 1,
) -> list[str]:
    clean_hostnames = extract_hostnames(hostnames)
    if not clean_hostnames:
        return []

    # DEBUG DUMP 1: Input file
    try:
        Path("debug_dnsx_input.txt").write_text("\n".join(clean_hostnames) + "\n", encoding="utf-8")
        console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved DNSx input targets to [bold green]debug_dnsx_input.txt[/bold green] ({len(clean_hostnames)} hosts)")
    except Exception:
        pass

    temp_targets_file = write_temp_targets(clean_hostnames, prefix="recon_dnsx_")

    args = [
        "-l", str(temp_targets_file),
        "-silent",
        "-json",
        "-resp",
        "-a",
        "-aaaa",
        "-cname",
    ]

    try:
        result = run_tool(
            tool_name="dnsx",
            args=args,
            stage_name="dns_resolve",
            run_id=run_id,
            timeout=timeout,
            retries=retries,
        )
    finally:
        temp_targets_file.unlink(missing_ok=True)

    # DEBUG DUMP 2: Raw output file
    try:
        Path("debug_dnsx_raw_output.txt").write_text(result.stdout, encoding="utf-8")
        console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved DNSx raw output to [bold green]debug_dnsx_raw_output.txt[/bold green] ({len(result.stdout)} bytes)")
    except Exception:
        pass

    # Parse stdout/raw NDJSON output into DnsxResult objects
    dns_results: list[DnsxResult] = parse_dnsx_output(result.stdout)

    live_hostnames: list[str] = []
    seen: set[str] = set()

    for item in dns_results:
        hostname = item.hostname
        if hostname in seen:
            continue

        # Enforce scope guardrails
        if scope_evaluator and not scope_evaluator.is_in_scope(hostname):
            continue

        # Ensure asset exists in DB and retrieve its integer asset_id
        _, root_domain, canonical_key = canonicalize_hostname(hostname)
        asset_id = upsert_asset(
            canonical_key=canonical_key,
            hostname=hostname,
            root_domain=root_domain,
            run_id=run_id,
            tool_result_id=result.tool_result_id,
        )

        seen.add(hostname)
        live_hostnames.append(hostname)

        # Record A / AAAA / CNAME records
        for record_type, values in item.records.items():
            for val in values:
                insert_dns_record(
                    asset_id=asset_id,
                    record_type=record_type,
                    value=val,
                    source_tool_result_id=result.tool_result_id,
                )

    # DEBUG DUMP 3: Filtered output file
    try:
        Path("debug_dnsx_filtered_output.txt").write_text("\n".join(live_hostnames) + "\n", encoding="utf-8")
        console.print(f"[bold yellow][DEBUG DUMP][/bold yellow] Saved DNSx filtered output to [bold green]debug_dnsx_filtered_output.txt[/bold green] ({len(live_hostnames)} hosts)")
    except Exception:
        pass

    return live_hostnames

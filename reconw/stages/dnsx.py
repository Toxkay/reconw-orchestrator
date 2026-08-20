"""Stage 2: DNS Resolution using DNSx.

Resolves discovered subdomains, records A/AAAA/CNAME entries into SQLite,
and filters out non-resolving or dead hosts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from reconw.scope.validator import DomainValidator, ScopeEvaluator
from reconw.storage.repository import insert_dns_record, upsert_asset
from reconw.tools.parser import DnsxResult, parse_dnsx_output
from reconw.tools.runner import run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_hostname


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
    """Executes the DNSx resolution stage.

    Args:
        hostnames: Discovered subdomains from Subfinder and seed scope.
        run_id: Pipeline run ID for SQLite tracking.
        scope_evaluator: Optional evaluator to enforce scope boundaries.
        timeout: Subprocess execution timeout in seconds.
        retries: Number of retry attempts on failure.

    Returns:
        List of live, resolvable hostnames.
    """
    clean_hostnames = extract_hostnames(hostnames)
    if not clean_hostnames:
        return []

    # Write target hostnames to a temporary file for dnsx
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

        # Record all resolved DNS records (A, AAAA, CNAME)
        for rec in item.records:
            insert_dns_record(
                asset_id=asset_id,
                record_type=rec.record_type,
                value=rec.value,
                source_tool_result_id=result.tool_result_id,
            )

        # Only return hostnames that actually resolved
        if item.is_resolved and item.records:
            seen.add(hostname)
            live_hostnames.append(hostname)

    return live_hostnames

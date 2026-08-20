"""Stage 1: Subdomain Enumeration using Subfinder.

Discovers passive subdomains for authorized in-scope root domains,
enforces scope boundaries, and records discovered assets into SQLite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from reconw.scope.validator import DomainValidator, ScopeEvaluator
from reconw.storage.repository import upsert_asset
from reconw.tools.parser import SubfinderAsset, parse_subfinder_output
from reconw.tools.runner import run_tool, write_temp_targets


def extract_root_domains(domains: Sequence[str]) -> list[str]:
    """Extracts clean unique root domains from in-scope targets for Subfinder."""
    roots: set[str] = set()
    for d in domains:
        clean = d.strip()
        if not clean:
            continue
        if clean.startswith("*."):
            clean = clean[2:]
        canonical = DomainValidator.canonicalize(clean)
        if canonical:
            roots.add(canonical)
    return sorted(roots)


def run_subfinder(
    in_scope_domains: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    concurrency: int = 20,
    timeout: int = 300,
    retries: int = 1,
) -> list[str]:
    root_domains = extract_root_domains(in_scope_domains)
    if not root_domains:
        return []

    # Write target root domains to a temporary file for subfinder
    temp_targets_file = write_temp_targets(root_domains, prefix="recon_subfinder_")

    args = [
        "-dL", str(temp_targets_file),
        "-silent",
        "-json",
        "-c", str(concurrency),
    ]

    try:
        result = run_tool(
            tool_name="subfinder",
            args=args,
            stage_name="subdomain_enum",
            run_id=run_id,
            timeout=timeout,
            retries=retries,
        )
    finally:
        temp_targets_file.unlink(missing_ok=True)

    # Parse stdout/raw NDJSON output into SubfinderAsset objects
    assets: list[SubfinderAsset] = parse_subfinder_output(result.stdout)

    discovered_hostnames: list[str] = []
    seen: set[str] = set()

    for asset in assets:
        hostname = asset.hostname
        if hostname in seen:
            continue

        # Enforce scope guardrails
        if scope_evaluator and not scope_evaluator.is_in_scope(hostname):
            continue

        seen.add(hostname)
        discovered_hostnames.append(hostname)

        # Persist asset in SQLite with provenance link to tool_result_id
        upsert_asset(
            canonical_key=asset.canonical_key,
            hostname=asset.hostname,
            root_domain=asset.root_domain,
            run_id=run_id,
            tool_result_id=result.tool_result_id,
        )

    return discovered_hostnames

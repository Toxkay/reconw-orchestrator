"""Stage 1: Subdomain Enumeration using Subfinder.

Discovers passive subdomains for authorized in-scope root domains,
enforces scope boundaries, and records discovered assets into SQLite.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

from rich.console import Console

from reconw.scope.validator import DomainValidator, ScopeEvaluator
from reconw.storage.repository import upsert_asset
from reconw.tools.parser import SubfinderAsset, parse_subfinder_output
from reconw.tools.runner import resolve_tool_binary, run_tool, write_temp_targets
from reconw.utils.canonical import canonicalize_hostname

console = Console(highlight=False)


def extract_root_domains(domains: Sequence[str]) -> list[str]:
    """Extracts clean unique root domains from in-scope targets for Subfinder."""
    roots: set[str] = set()
    for d in domains:
        clean = d.strip()
        if not clean:
            continue
        if clean.startswith("*."):
            clean = clean[2:]
        _, root_domain, _ = canonicalize_hostname(clean)
        if root_domain:
            roots.add(root_domain)
        else:
            canonical = DomainValidator.canonicalize(clean)
            if canonical:
                roots.add(canonical)
    return sorted(roots)


def run_subfinder(
    in_scope_domains: Sequence[str],
    run_id: int,
    scope_evaluator: ScopeEvaluator | None = None,
    timeout: int = 300,
    retries: int = 1,
) -> list[str]:
    root_domains = extract_root_domains(in_scope_domains)
    if not root_domains:
        console.print("[dim][DEBUG subfinder][/dim] No root domains to enumerate.")
        return []

    binary_path = resolve_tool_binary("subfinder")
    console.print(f"[dim][DEBUG subfinder][/dim] Binary resolved: [cyan]{binary_path}[/cyan]")
    console.print(f"[dim][DEBUG subfinder][/dim] Target root domains ({len(root_domains)}): {', '.join(root_domains[:5])}{'...' if len(root_domains) > 5 else ''}")

    temp_targets_file = write_temp_targets(root_domains, prefix="recon_subfinder_")

    # Official Subfinder flags:
    # -dL: File containing list of domains for subdomain discovery
    # -silent: Show only subdomains in output
    # -oJ: Write output in JSONL format
    # -all: Use all passive sources for maximum discovery
    # -cs: Include discovery sources in JSON output
    args = [
        "-dL", str(temp_targets_file),
        "-silent",
        "-oJ",
        "-all",
        "-cs",
    ]

    try:
        console.print(f"[dim][DEBUG subfinder][/dim] Running command: `{' '.join([str(binary_path)] + args)}`")
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

    console.print(f"[dim][DEBUG subfinder][/dim] Exit code: {result.exit_code}, Output length: {len(result.stdout)} bytes")
    if result.stderr and result.exit_code != 0:
        console.print(f"[bold red][DEBUG subfinder stderr][/bold red] {result.stderr.strip()[:300]}")

    # Parse stdout/raw NDJSON output into SubfinderAsset objects
    assets: list[SubfinderAsset] = parse_subfinder_output(result.stdout)
    console.print(f"[dim][DEBUG subfinder][/dim] Parsed {len(assets)} raw subdomains from output")

    discovered_hostnames: list[str] = []
    seen: set[str] = set()
    filtered_out_count = 0

    for asset in assets:
        hostname = asset.hostname
        if hostname in seen:
            continue

        # Enforce scope guardrails
        if scope_evaluator and not scope_evaluator.is_in_scope(hostname):
            filtered_out_count += 1
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

    if filtered_out_count > 0:
        console.print(f"[dim][DEBUG subfinder][/dim] {filtered_out_count} subdomains were filtered out by scope rules.")

    return discovered_hostnames

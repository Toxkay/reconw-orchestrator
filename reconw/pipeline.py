"""Pipeline Conductor for ReconW.

Chains together the 5 reconnaissance stages sequentially:
Subfinder -> DNSx -> HTTPx -> Katana -> Prioritize -> HTML Report.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from reconw.report.generator import render_html_report
from reconw.scope.loader import load_targets
from reconw.scope.validator import DomainValidator, ScopeEvaluator
from reconw.stages.dnsx import run_dnsx
from reconw.stages.httpx import run_httpx
from reconw.stages.katana import run_katana
from reconw.stages.prioritize import EndpointScore, run_prioritize
from reconw.stages.subfinder import run_subfinder
from reconw.storage.repository import create_run, finish_run


@dataclass(slots=True)
class ReconTargets:
    """Validated in-scope and out-of-scope targets."""
    in_scope: list[str]
    out_of_scope: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PipelineSummary:
    """Summary of findings after a pipeline execution."""
    run_id: int
    program_name: str
    subdomains_count: int
    resolved_hosts_count: int
    live_endpoints_count: int
    crawled_urls_count: int
    critical_count: int
    high_count: int
    duration_seconds: float
    report_path: Path | None = None


def _validate_targets(targets: Sequence[str]) -> list[str]:
    """Validates domain syntax and removes duplicates."""
    validated: list[str] = []
    for target in targets:
        clean = target.strip()
        if not clean:
            continue
        validated.append(DomainValidator.validate(clean))
    return DomainValidator.remove_duplicates(validated)


def build_targets(in_scope_file: Path, out_of_scope_file: Path | None = None) -> ReconTargets:
    """Load and validate scope text files into normalized target lists."""
    in_targets = _validate_targets(load_targets(in_scope_file))
    out_targets = _validate_targets(load_targets(out_of_scope_file)) if out_of_scope_file else []
    return ReconTargets(in_scope=in_targets, out_of_scope=out_targets)


def run_pipeline(
    program_name: str,
    targets: ReconTargets,
    cli_args: str = "",
    enable_crawler: bool = True,
    generate_report: bool = True,
    reports_dir: Path | str = Path("reports"),
) -> PipelineSummary:
    """Executes the full 5-stage reconnaissance pipeline and generates an HTML report.

    Args:
        program_name: Required name of the target program/organization.
        targets: Validated ReconTargets (in-scope and out-of-scope lists).
        cli_args: Optional CLI string for audit logging in the `run` table.
        enable_crawler: Whether to run active shallow crawling (Katana).
        generate_report: Whether to generate a static HTML report at the end.
        reports_dir: Directory where the generated report will be saved.

    Returns:
        PipelineSummary with execution metrics and report path.
    """
    t0 = time.perf_counter()

    # 1. Initialize Scope Evaluator & SQLite Run Record
    evaluator = ScopeEvaluator(in_scope=targets.in_scope, out_of_scope=targets.out_of_scope)
    run_id = create_run(
        program_name=program_name,
        status="RUNNING",
        cli_args=cli_args,
    )

    try:
        # ==========================================================
        # STAGE 1: Subdomain Enumeration (Subfinder)
        # ==========================================================
        subdomains = run_subfinder(
            in_scope_domains=targets.in_scope,
            run_id=run_id,
            scope_evaluator=evaluator,
        )

        combined_hosts = list(set(targets.in_scope + subdomains))

        # ==========================================================
        # STAGE 2: DNS Resolution (DNSx)
        # ==========================================================
        resolved_hosts = run_dnsx(
            hostnames=combined_hosts,
            run_id=run_id,
            scope_evaluator=evaluator,
        )

        # ==========================================================
        # STAGE 3: HTTP Probing & Screenshots (HTTPx)
        # ==========================================================
        hosts_to_probe = resolved_hosts if resolved_hosts else combined_hosts
        live_endpoints = run_httpx(
            targets=hosts_to_probe,
            run_id=run_id,
            scope_evaluator=evaluator,
        )

        # ==========================================================
        # STAGE 4: Shallow Crawling (Katana)
        # ==========================================================
        crawled_urls: list[str] = []
        if enable_crawler and live_endpoints:
            crawled_urls = run_katana(
                seed_urls=live_endpoints,
                run_id=run_id,
                scope_evaluator=evaluator,
            )

        # ==========================================================
        # STAGE 5: Prioritization & Scoring Engine (Pure Python)
        # ==========================================================
        scores: list[EndpointScore] = run_prioritize(run_id=run_id)

        # ==========================================================
        # STAGE 6: Generate HTML Report
        # ==========================================================
        report_path: Path | None = None
        if generate_report:
            report_path = render_html_report(run_id=run_id, reports_dir=reports_dir)

        # Mark Run as COMPLETED in SQLite
        finish_run(run_id, status="COMPLETED")

        duration = round(time.perf_counter() - t0, 2)
        critical_count = sum(1 for s in scores if s.band == "Critical")
        high_count = sum(1 for s in scores if s.band == "High")

        return PipelineSummary(
            run_id=run_id,
            program_name=program_name,
            subdomains_count=len(subdomains),
            resolved_hosts_count=len(resolved_hosts),
            live_endpoints_count=len(live_endpoints),
            crawled_urls_count=len(crawled_urls),
            critical_count=critical_count,
            high_count=high_count,
            duration_seconds=duration,
            report_path=report_path,
        )

    except Exception as exc:
        finish_run(run_id, status="FAILED")
        raise exc

"""HTML Report Generator for ReconW.

Queries the SQLite database for a given run ID, aggregates metrics,
and renders a self-contained, offline-compatible HTML report.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reconw.storage.repository import (
    get_all_endpoints_for_run,
    get_assets_for_run,
    get_run,
    get_scores_for_run,
    get_tool_results_for_run,
    get_urls_for_run,
)

TEMPLATES_DIR = Path(__file__).parent / "templates"


def slugify(text: str) -> str:
    """Converts text into a clean lowercase file slug."""
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", text.strip().lower())
    return slug.strip("_") or "reconw"


def generate_report_data(run_id: int) -> dict[str, Any]:
    """Assembles all run records from SQLite into a structured report dictionary."""
    run_meta = get_run(run_id) or {
        "id": run_id,
        "program_name": "Unknown Program",
        "started_at": "Unknown",
        "finished_at": "Unknown",
        "status": "COMPLETED",
        "cli_args": "reconw run",
    }

    program_name = run_meta.get("program_name") or "Unknown Program"
    assets = get_assets_for_run(run_id)
    endpoints = get_all_endpoints_for_run(run_id)
    urls = get_urls_for_run(run_id)
    scores = get_scores_for_run(run_id)
    tool_results = get_tool_results_for_run(run_id)

    # Process scores and parse breakdowns & tech stacks
    processed_scores: list[dict[str, Any]] = []
    tech_counter: Counter[str] = Counter()
    critical_count = 0
    high_count = 0

    for s in scores:
        band = s.get("band") or "Info"
        if band == "Critical":
            critical_count += 1
        elif band == "High":
            high_count += 1

        # Parse score breakdown JSON
        raw_breakdown = s.get("score_breakdown_json") or "{}"
        try:
            breakdown = json.loads(raw_breakdown) if isinstance(raw_breakdown, str) else raw_breakdown
        except json.JSONDecodeError:
            breakdown = {}

        # Parse tech stack JSON
        raw_tech = s.get("tech_stack_json") or "[]"
        try:
            tech_list = json.loads(raw_tech) if isinstance(raw_tech, str) else raw_tech
            if not isinstance(tech_list, list):
                tech_list = [str(tech_list)]
        except json.JSONDecodeError:
            tech_list = []

        for t in tech_list:
            if t.strip():
                tech_counter[t.strip()] += 1

        processed_scores.append({
            **s,
            "breakdown": breakdown,
            "tech_list": tech_list,
        })

    # Prepare JSON blob for client-side export
    data_blob = {
        "program_name": program_name,
        "run": run_meta,
        "summary": {
            "subdomains_count": len(assets),
            "endpoints_count": len(endpoints),
            "crawled_urls_count": len(urls),
            "critical_count": critical_count,
            "high_count": high_count,
        },
        "scores": processed_scores,
        "assets": assets,
        "endpoints": endpoints,
        "urls": urls,
        "tool_results": tool_results,
    }

    return {
        "program_name": program_name,
        "run": run_meta,
        "assets": assets,
        "endpoints": endpoints,
        "urls": urls,
        "scores": processed_scores,
        "tool_results": tool_results,
        "critical_count": critical_count,
        "high_count": high_count,
        "tech_distribution": dict(tech_counter.most_common(20)),
        "json_blob": json.dumps(data_blob),
    }


def render_html_report(
    run_id: int,
    output_path: Path | str | None = None,
    reports_dir: Path | str = Path("reports"),
) -> Path:
    """Renders and writes a standalone HTML report for the specified run ID."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")

    report_context = generate_report_data(run_id)
    program_name = report_context.get("program_name") or "target"
    prog_slug = slugify(program_name)
    rendered_html = template.render(**report_context)

    if output_path:
        out_file = Path(output_path)
    else:
        dir_path = Path(reports_dir)
        dir_path.mkdir(parents=True, exist_ok=True)
        out_file = dir_path / f"report_{prog_slug}_{run_id}.html"

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(rendered_html, encoding="utf-8")
    return out_file

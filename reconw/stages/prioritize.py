"""Stage 5: Rule-Based Prioritization & Scoring Engine.

Evaluates discovered endpoints and crawled URLs against security-relevant heuristics,
calculating an explainable score, severity band, and score breakdown.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from reconw.storage.repository import (
    get_all_endpoints_for_run,
    insert_score,
)

RULES_VERSION = "v1.0"

# Admin / Auth / Control panel patterns
ADMIN_KEYWORDS = {
    "admin", "login", "signin", "dashboard", "portal",
    "manage", "management", "controlpanel", "cpanel", "phpmyadmin",
    "grafana", "kibana", "jenkins", "administrator",
}

# Sensitive / high-value API and internal patterns (matches in path or subdomain)
SENSITIVE_PATTERNS = {
    "api", "internal", "staging", "backup", "backups", "test",
    "debug", ".git", ".env", "v1", "v2", "v3", "graphql",
    "swagger", "openapi", "actuator", "console", "config",
    "secrets", "private", "metrics", "server-status", "dev",
}

NOTABLE_TECHS = {
    "wordpress", "jenkins", "spring", "spring boot", "laravel",
    "django", "grafana", "kibana", "swagger", "php", "apache tomcat",
    "weblogic", "struts", "coldfusion", "drupal", "jira", "confluence",
    "git", "docker", "kubernetes",
}

PARKING_KEYWORDS = {
    "domain for sale", "parked domain", "under construction",
    "default page", "coming soon", "buy this domain",
}


@dataclass(slots=True)
class EndpointScore:
    """Calculated score and breakdown for an endpoint."""
    endpoint_id: int
    url: str
    score: int
    band: str
    breakdown: dict[str, int] = field(default_factory=dict)


def calculate_endpoint_score(endpoint_data: dict[str, Any]) -> EndpointScore:
    """Calculates the priority score and rule breakdown for an endpoint."""
    endpoint_id = int(endpoint_data.get("id") or 0)
    url = str(endpoint_data.get("url") or "")
    title = str(endpoint_data.get("title") or "").lower()
    status_code = int(endpoint_data.get("status_code") or 0)
    content_length = int(endpoint_data.get("content_length") or 0)

    # Parse tech stack from JSON string or list
    raw_tech = endpoint_data.get("tech_stack_json") or "[]"
    tech_stack: list[str] = []
    if isinstance(raw_tech, str):
        try:
            tech_stack = json.loads(raw_tech)
        except json.JSONDecodeError:
            tech_stack = [raw_tech.lower()]
    elif isinstance(raw_tech, list):
        tech_stack = [str(t).lower() for t in raw_tech]

    parsed = urlparse(url.lower())
    hostname = parsed.hostname or ""
    path_segments = [p for p in parsed.path.split("/") if p]
    query_string = parsed.query

    score = 0
    breakdown: dict[str, int] = {}

    # 1. Admin / Login / Dashboard Keywords (+30)
    # Check title, URL path, or query
    search_text = f"{title} {parsed.path} {query_string}"
    admin_matched = [
        k for k in ADMIN_KEYWORDS
        if re.search(rf"\b{re.escape(k)}\b", search_text, re.IGNORECASE) or k in parsed.path
    ]
    # Check auth / sso as distinct words
    if re.search(r"\b(auth|sso)\b", search_text, re.IGNORECASE):
        admin_matched.append("auth")

    if admin_matched:
        pts = 30
        score += pts
        breakdown[f"admin_keyword ({', '.join(sorted(set(admin_matched))[:3])})"] = pts

    # 2. Sensitive / Interesting Path or Subdomain (+20)
    subdomain_parts = hostname.split(".")
    sensitive_matched = [
        s for s in SENSITIVE_PATTERNS
        if any(s == seg or s in seg for seg in path_segments) or any(s == sub for sub in subdomain_parts)
    ]
    if sensitive_matched:
        pts = 20
        score += pts
        breakdown[f"sensitive_path ({', '.join(sorted(set(sensitive_matched))[:3])})"] = pts

    # 3. Notable / Vulnerability-Prone Tech Stack (+15)
    matched_techs = [t for t in tech_stack if any(nt in t.lower() for nt in NOTABLE_TECHS)]
    if matched_techs:
        pts = 15
        score += pts
        breakdown[f"notable_tech ({', '.join(sorted(set(matched_techs))[:3])})"] = pts

    # 4. Protected Status 401 / 403 (+10)
    if status_code in {401, 403}:
        pts = 10
        score += pts
        breakdown[f"protected_status ({status_code})"] = pts

    # 5. Live 200 with Non-Trivial Content (+10)
    if status_code == 200 and content_length > 0:
        pts = 10
        score += pts
        breakdown["live_200_response"] = pts

    # 6. Empty / Parking Page Heuristic (-10)
    if content_length == 0 or any(pk in title for pk in PARKING_KEYWORDS):
        pts = -10
        score += pts
        breakdown["empty_or_parking_page"] = pts

    # Cap score bounds between 0 and 100
    final_score = max(0, min(100, score))

    # Assign severity band
    if final_score >= 70:
        band = "Critical"
    elif final_score >= 50:
        band = "High"
    elif final_score >= 30:
        band = "Medium"
    elif final_score >= 10:
        band = "Low"
    else:
        band = "Info"

    return EndpointScore(
        endpoint_id=endpoint_id,
        url=url,
        score=final_score,
        band=band,
        breakdown=breakdown,
    )


def run_prioritize(run_id: int) -> list[EndpointScore]:
    """Executes Stage 5: Rule-based prioritization for all endpoints in a run.

    Args:
        run_id: Current pipeline run identifier.

    Returns:
        List of computed EndpointScore objects ordered by score descending.
    """
    endpoints = get_all_endpoints_for_run(run_id)
    if not endpoints:
        return []

    scored_endpoints: list[EndpointScore] = []

    for ep in endpoints:
        ep_score = calculate_endpoint_score(ep)
        scored_endpoints.append(ep_score)

        # Persist to SQLite score table
        insert_score(
            run_id=run_id,
            endpoint_id=ep_score.endpoint_id,
            score=ep_score.score,
            band=ep_score.band,
            score_breakdown_json=json.dumps(ep_score.breakdown),
            rules_version=RULES_VERSION,
        )

    # Sort descending by score
    scored_endpoints.sort(key=lambda x: x.score, reverse=True)
    return scored_endpoints

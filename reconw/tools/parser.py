"""JSONL and NDJSON parsers for external security tools (Subfinder, Dnsx, Httpx, Katana).

Provides robust, typed extraction of discovered assets, DNS records, HTTP endpoints,
and crawled URLs from tool outputs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlparse

from reconw.utils.canonical import canonicalize_hostname, canonicalize_url


# =====================================================================
# Data Models
# =====================================================================

@dataclass(slots=True)
class SubfinderAsset:
    """Discovered subdomain from Subfinder."""
    hostname: str
    root_domain: str
    canonical_key: str
    input_domain: str = ""
    sources: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DnsRecordItem:
    """Individual DNS record resolution."""
    record_type: str  # A, AAAA, CNAME, etc.
    value: str


@dataclass(slots=True)
class DnsxResult:
    """DNS resolution result from Dnsx."""
    hostname: str
    canonical_key: str
    records: list[DnsRecordItem] = field(default_factory=list)
    status_code: str = "NOERROR"
    is_resolved: bool = True


@dataclass(slots=True)
class HttpxEndpoint:
    """Live HTTP probe result from Httpx."""
    url: str
    hostname: str
    dedup_key: str
    status_code: int
    content_length: int
    title: str = ""
    tech_stack: list[str] = field(default_factory=list)
    screenshot_path: str = ""
    webserver: str = ""
    host_ip: str = ""
    raw_response_snippet: str = ""


@dataclass(slots=True)
class KatanaUrlItem:
    """Discovered URL from Katana crawler."""
    url: str
    dedup_key: str
    source_endpoint: str = ""
    tag: str = ""
    method: str = "GET"


# =====================================================================
# Stream / File Helper
# =====================================================================

def _load_raw_content(source: str | Path | Sequence[dict[str, Any]]) -> list[dict[str, Any]] | list[str]:
    """Unifies raw input from string, Path, or pre-parsed dicts into lines or dicts."""
    if isinstance(source, Path):
        if not source.exists():
            return []
        text = source.read_text(encoding="utf-8", errors="replace")
        return [l.strip() for l in text.splitlines() if l.strip()]
    elif isinstance(source, str):
        return [l.strip() for l in source.splitlines() if l.strip()]
    elif isinstance(source, (list, tuple)):
        return list(source)
    return []


# =====================================================================
# 1. Subfinder Parser
# =====================================================================

def parse_subfinder_output(
    source: str | Path | Sequence[dict[str, Any]]
) -> list[SubfinderAsset]:
    """Parses Subfinder JSONL or line-by-line output into SubfinderAsset items."""
    items = _load_raw_content(source)
    results: list[SubfinderAsset] = []
    seen_keys: set[str] = set()

    for item in items:
        host = ""
        input_dom = ""
        sources: list[str] = []

        if isinstance(item, dict):
            host = item.get("host") or item.get("hostname") or ""
            input_dom = item.get("input") or ""
            raw_sources = item.get("sources") or item.get("source") or []
            if isinstance(raw_sources, list):
                sources = [str(s) for s in raw_sources]
            elif isinstance(raw_sources, str):
                sources = [raw_sources]
        elif isinstance(item, str):
            clean_line = item.strip()
            if not clean_line:
                continue
            if clean_line.startswith("{") and clean_line.endswith("}"):
                try:
                    data = json.loads(clean_line)
                    host = data.get("host") or data.get("hostname") or ""
                    input_dom = data.get("input") or ""
                    raw_sources = data.get("sources") or data.get("source") or []
                    if isinstance(raw_sources, list):
                        sources = [str(s) for s in raw_sources]
                    elif isinstance(raw_sources, str):
                        sources = [raw_sources]
                except json.JSONDecodeError:
                    host = clean_line
            else:
                host = clean_line

        if not host:
            continue

        normalized_host, root_domain, canonical_key = canonicalize_hostname(host)
        if not normalized_host or canonical_key in seen_keys:
            continue

        seen_keys.add(canonical_key)
        results.append(
            SubfinderAsset(
                hostname=normalized_host,
                root_domain=root_domain,
                canonical_key=canonical_key,
                input_domain=input_dom,
                sources=sources,
            )
        )

    return results


# =====================================================================
# 2. Dnsx Parser
# =====================================================================

def parse_dnsx_output(
    source: str | Path | Sequence[dict[str, Any]]
) -> list[DnsxResult]:
    """Parses Dnsx JSON output into DnsxResult items with DNS records."""
    items = _load_raw_content(source)
    results: list[DnsxResult] = []
    seen_keys: set[str] = set()

    for item in items:
        data: dict[str, Any] = {}
        if isinstance(item, dict):
            data = item
        elif isinstance(item, str):
            clean = item.strip()
            if not clean:
                continue
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                except json.JSONDecodeError:
                    continue
            else:
                parts = clean.split()
                if parts:
                    data = {"host": parts[0]}

        host = data.get("host") or ""
        if not host:
            continue

        normalized_host, _, canonical_key = canonicalize_hostname(host)
        if not normalized_host or canonical_key in seen_keys:
            continue

        records: list[DnsRecordItem] = []

        for ip in data.get("a") or []:
            if isinstance(ip, str) and ip.strip():
                records.append(DnsRecordItem(record_type="A", value=ip.strip()))

        for ip6 in data.get("aaaa") or []:
            if isinstance(ip6, str) and ip6.strip():
                records.append(DnsRecordItem(record_type="AAAA", value=ip6.strip()))

        for cname in data.get("cname") or []:
            if isinstance(cname, str) and cname.strip():
                records.append(DnsRecordItem(record_type="CNAME", value=cname.strip()))

        for mx in data.get("mx") or []:
            if isinstance(mx, str) and mx.strip():
                records.append(DnsRecordItem(record_type="MX", value=mx.strip()))

        status_code = data.get("status_code") or "NOERROR"
        is_resolved = len(records) > 0 or status_code == "NOERROR"

        seen_keys.add(canonical_key)
        results.append(
            DnsxResult(
                hostname=normalized_host,
                canonical_key=canonical_key,
                records=records,
                status_code=status_code,
                is_resolved=is_resolved,
            )
        )

    return results


# =====================================================================
# 3. Httpx Parser
# =====================================================================

def parse_httpx_output(
    source: str | Path | Sequence[dict[str, Any]]
) -> list[HttpxEndpoint]:
    """Parses Httpx JSON probe output into HttpxEndpoint items."""
    items = _load_raw_content(source)
    results: list[HttpxEndpoint] = []
    seen_dedup: set[str] = set()

    for item in items:
        data: dict[str, Any] = {}
        if isinstance(item, dict):
            data = item
        elif isinstance(item, str):
            clean = item.strip()
            if not clean:
                continue
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                except json.JSONDecodeError:
                    continue
            else:
                data = {"url": clean, "status_code": 200, "content_length": 0}

        raw_url = data.get("url") or ""
        if not raw_url:
            continue

        normalized_url, dedup_key = canonicalize_url(raw_url)
        if dedup_key in seen_dedup:
            continue

        parsed_url = urlparse(normalized_url)
        hostname = parsed_url.hostname or ""

        raw_tech = data.get("tech") or data.get("technologies") or []
        tech_list: list[str] = []
        if isinstance(raw_tech, list):
            tech_list = [str(t).strip() for t in raw_tech if str(t).strip()]
        elif isinstance(raw_tech, str):
            tech_list = [t.strip() for t in raw_tech.split(",") if t.strip()]

        status_code = int(data.get("status_code") or data.get("status-code") or 0)
        content_length = int(data.get("content_length") or data.get("content-length") or 0)
        title = str(data.get("title") or "").strip()
        screenshot_path = str(data.get("screenshot_path") or data.get("stored_response_path") or "").strip()
        webserver = str(data.get("webserver") or "").strip()
        host_ip = str(data.get("host") or "").strip()

        seen_dedup.add(dedup_key)
        results.append(
            HttpxEndpoint(
                url=normalized_url,
                hostname=hostname,
                dedup_key=dedup_key,
                status_code=status_code,
                content_length=content_length,
                title=title,
                tech_stack=tech_list,
                screenshot_path=screenshot_path,
                webserver=webserver,
                host_ip=host_ip,
            )
        )

    return results


# =====================================================================
# 4. Katana Parser
# =====================================================================

def parse_katana_output(
    source: str | Path | Sequence[dict[str, Any]]
) -> list[KatanaUrlItem]:
    """Parses Katana crawler JSON output into KatanaUrlItem items."""
    items = _load_raw_content(source)
    results: list[KatanaUrlItem] = []
    seen_dedup: set[str] = set()

    for item in items:
        raw_url = ""
        tag = ""
        source_endpoint = ""
        method = "GET"

        if isinstance(item, dict):
            req = item.get("request") or {}
            raw_url = req.get("endpoint") or req.get("url") or item.get("url") or item.get("endpoint") or ""
            tag = req.get("tag") or item.get("tag") or ""
            source_endpoint = req.get("source") or item.get("source") or ""
            method = req.get("method") or item.get("method") or "GET"
        elif isinstance(item, str):
            clean = item.strip()
            if not clean:
                continue
            if clean.startswith("{") and clean.endswith("}"):
                try:
                    data = json.loads(clean)
                    req = data.get("request") or {}
                    raw_url = req.get("endpoint") or req.get("url") or data.get("url") or ""
                    tag = req.get("tag") or data.get("tag") or ""
                    source_endpoint = req.get("source") or data.get("source") or ""
                    method = req.get("method") or data.get("method") or "GET"
                except json.JSONDecodeError:
                    raw_url = clean
            else:
                raw_url = clean

        if not raw_url:
            continue

        normalized_url, dedup_key = canonicalize_url(raw_url)
        if dedup_key in seen_dedup:
            continue

        seen_dedup.add(dedup_key)
        results.append(
            KatanaUrlItem(
                url=normalized_url,
                dedup_key=dedup_key,
                source_endpoint=source_endpoint,
                tag=tag,
                method=method,
            )
        )

    return results

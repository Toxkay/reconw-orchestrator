"""Canonicalization and normalization utilities for hostnames and URLs.

Provides deterministic dedup keys and standard normalization rules across all stages.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def canonicalize_hostname(hostname: str) -> tuple[str, str, str]:
    """Normalizes a hostname and computes root domain and canonical key."""
    clean = hostname.strip().lower()

    if clean.startswith("http://"):
        clean = clean[7:]
    elif clean.startswith("https://"):
        clean = clean[8:]

    # Remove path or query if present
    clean = clean.split("/")[0].split("?")[0]

    # Remove port if present
    if ":" in clean:
        clean = clean.split(":")[0]

    # Strip trailing dot and brackets
    clean = clean.rstrip(".").strip("[]")

    # Extract root domain
    parts = clean.split(".")
    if len(parts) >= 2:
        if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "edu"} and len(parts[-1]) <= 3:
            root_domain = ".".join(parts[-3:])
        else:
            root_domain = ".".join(parts[-2:])
    else:
        root_domain = clean

    canonical_key = clean
    return clean, root_domain, canonical_key


def canonicalize_url(raw_url: str) -> tuple[str, str]:
    """Canonicalizes a URL and generates a deterministic dedup key safely.

    Handles edge cases like malformed IPv6 brackets or unparseable URLs.
    """
    clean = raw_url.strip()
    if not clean.lower().startswith("http://") and not clean.lower().startswith("https://"):
        clean = "https://" + clean

    try:
        parsed = urlparse(clean)

        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Strip standard default ports
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]

        # Normalize path
        path = parsed.path or ""
        if path:
            path = re.sub(r"/+", "/", path)
            if len(path) > 1 and path.endswith("/"):
                path = path.rstrip("/")

        # Sort query parameters
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params))

        # Normalized URL without fragment
        normalized = urlunparse((scheme, netloc, path, "", sorted_query, ""))
        dedup_key = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
        return normalized, dedup_key

    except Exception:
        # Fallback for malformed URLs (e.g. invalid IPv6 brackets in JS files)
        safe_url = clean.split("#")[0]
        dedup_key = hashlib.sha256(safe_url.encode("utf-8")).hexdigest()[:16]
        return safe_url, dedup_key

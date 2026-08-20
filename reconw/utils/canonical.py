"""Canonicalization and normalization utilities for hostnames and URLs.

Provides deterministic dedup keys and standard normalization rules across all stages.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def canonicalize_hostname(hostname: str) -> tuple[str, str, str]:
    """Normalizes a hostname and computes root domain and canonical key.

    Rules:
        1. Lowercase and strip whitespace.
        2. Remove protocol (http://, https://).
        3. Remove port numbers if present (:80, :443, etc.).
        4. Strip trailing DNS dots.
        5. Extract root domain (e.g., 'sub.example.com' -> 'example.com').

    Returns:
        tuple[normalized_hostname, root_domain, canonical_key]
    """
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

    # Strip trailing dot
    clean = clean.rstrip(".")

    # Extract root domain (supports standard multi-part TLDs like .co.uk)
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
    """Canonicalizes a URL and generates a deterministic dedup key.

    Rules:
        1. Strip whitespace.
        2. Case-insensitive scheme detection (defaults to https if missing).
        3. Lowercase scheme and netloc (hostname + port without default 80/443).
        4. Path case is preserved, redundant slashes normalized.
        5. Query parameters are sorted alphabetically.
        6. Fragment (#anchor) is stripped.

    Returns:
        tuple[normalized_url, dedup_key]
    """
    clean = raw_url.strip()
    if not clean.lower().startswith("http://") and not clean.lower().startswith("https://"):
        clean = "https://" + clean

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

    # Dedup key hash
    dedup_key = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return normalized, dedup_key

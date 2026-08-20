import fnmatch
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


class DomainValidator:
    """Validates and canonicalizes domain targets, URLs, and wildcard patterns."""

    @staticmethod
    def validate(target: str) -> str:
        """
        Normalize and validate a domain target or wildcard pattern.
        Returns the canonical target or raises ValueError.
        """
        canonical = DomainValidator.canonicalize(target)
        if not canonical:
            raise ValueError("Target domain cannot be empty.")

        DomainValidator._check_domain(canonical)
        return canonical

    @staticmethod
    def canonicalize(target: str) -> str:
        """
        Canonicalize a domain/hostname/URL target:
        - Strips whitespace & lowercases
        - Strips protocol (http://, https://)
        - Strips path components (/api/, /v1, etc.)
        - Strips default web ports (:80, :443)
        - Strips trailing DNS dots
        """
        target = target.strip().lower()
        if not target:
            return ""

        # Strip protocol
        if target.startswith("http://"):
            target = target[7:]
        elif target.startswith("https://"):
            target = target[8:]

        # Strip any URL path (e.g. "dev*.playcanvas.com/api/" -> "dev*.playcanvas.com")
        if "/" in target:
            target = target.split("/")[0]

        # Strip default ports
        if target.endswith(":80"):
            target = target[:-3]
        elif target.endswith(":443"):
            target = target[:-4]

        # Strip trailing dot
        target = target.rstrip(".")
        return target

    @staticmethod
    def _check_domain(target: str) -> None:
        """Validate target domain/wildcard pattern syntax."""
        # Strip wildcards for characters validation
        clean_domain = target.replace("*", "a")

        if ":" in clean_domain:
            raise ValueError(f"Target '{target}' should not contain a port number.")

        if len(clean_domain) > 253:
            raise ValueError(f"Target '{target}' exceeds 253 character limit.")

        # Ensure valid domain/hostname format with dots
        if "." not in clean_domain and not clean_domain.startswith("localhost"):
            raise ValueError(f"Target '{target}' is not a valid domain name.")

    @staticmethod
    def remove_duplicates(targets: list[str]) -> list[str]:
        """Remove duplicate targets while preserving order."""
        seen = set()
        result = []
        for target in targets:
            if target in seen:
                continue
            seen.add(target)
            result.append(target)
        return result


class URLValidator:
    """Canonicalizes and validates URLs for deduplication."""

    @staticmethod
    def canonicalize(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()

        if ":" in netloc:
            host, port_str = netloc.rsplit(":", 1)
            host = host.rstrip(".")
            if (scheme == "http" and port_str == "80") or (scheme == "https" and port_str == "443"):
                netloc = host
            else:
                netloc = f"{host}:{port_str}"
        else:
            netloc = netloc.rstrip(".")

        path = parts.path or "/"
        path = re.sub(r"/{2,}", "/", path)

        query = ""
        if parts.query:
            params = parse_qsl(parts.query, keep_blank_values=True)
            params.sort(key=lambda x: (x[0], x[1]))
            query = urlencode(params)

        return urlunsplit((scheme, netloc, path, query, ""))


class ScopeEvaluator:
    """
    Evaluates whether discovered hosts or URLs are in-scope or out-of-scope.
    Supports exact domains, subdomains, and arbitrary wildcard globs (e.g. dev*.playcanvas.com, *us.tiktok.com).
    Strictly enforces deny-over-allow precedence.
    """

    def __init__(self, in_scope: list[str], out_of_scope: list[str] | None = None):
        self.in_scope = [DomainValidator.canonicalize(t) for t in in_scope if t.strip()]
        self.out_of_scope = [
            DomainValidator.canonicalize(t) for t in (out_of_scope or []) if t.strip()
        ]

    @staticmethod
    def match_pattern(target: str, pattern: str) -> bool:
        """
        Check if target matches a domain pattern:
        - Glob wildcard 'dev*.playcanvas.com' matches 'dev.playcanvas.com', 'dev1.playcanvas.com'
        - Prefix wildcard '*.example.com' matches 'sub.example.com' and 'example.com'
        - Suffix/infix wildcard '*us.tiktokv.com' matches 'us.tiktokv.com', 'api-us.tiktokv.com'
        - Root domain 'example.com' matches 'example.com' and 'sub.example.com'
        """
        target = DomainValidator.canonicalize(target)
        pattern = DomainValidator.canonicalize(pattern)

        if not target or not pattern:
            return False

        # 1. Exact match
        if target == pattern:
            return True

        # 2. Glob / Wildcard pattern matching
        if "*" in pattern:
            if fnmatch.fnmatchcase(target, pattern):
                return True
            # Also allow root domain when pattern is *.domain.com
            if pattern.startswith("*.") and target == pattern[2:]:
                return True
            return False

        # 3. Base domain matches subdomains (e.g. snapchat.com matches web.snapchat.com)
        if target.endswith("." + pattern):
            return True

        return False

    def is_out_of_scope(self, target: str) -> bool:
        """Returns True if target matches any out-of-scope rule."""
        canonical_target = DomainValidator.canonicalize(target)
        for pattern in self.out_of_scope:
            if self.match_pattern(canonical_target, pattern):
                return True
        return False

    def is_in_scope(self, target: str) -> bool:
        """
        Returns True if:
        1. Target does NOT match any out-of-scope rule.
        2. Target matches at least one in-scope rule.
        """
        canonical_target = DomainValidator.canonicalize(target)

        # 1. Deny rules take absolute precedence
        if self.is_out_of_scope(canonical_target):
            return False

        # 2. Must match an in-scope rule
        for pattern in self.in_scope:
            if self.match_pattern(canonical_target, pattern):
                return True

        return False

    def filter_targets(self, targets: list[str]) -> list[str]:
        """Filter a list of discovered targets, keeping only in-scope ones."""
        canonicalized = [DomainValidator.canonicalize(t) for t in targets if t.strip()]
        unique_targets = DomainValidator.remove_duplicates(canonicalized)
        return [t for t in unique_targets if self.is_in_scope(t)]

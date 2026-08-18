import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


class DomainValidator:
    """Validates and canonicalizes domain targets and wildcards."""

    @staticmethod
    def validate(target: str) -> str:
        """
        Normalize and validate a domain target.
        Returns the canonical target or raises ValueError.
        """
        target = DomainValidator.canonicalize(target)

        DomainValidator._check_path(target)
        DomainValidator._check_wildcard(target)
        DomainValidator._check_domain(target)

        return target

    @staticmethod
    def canonicalize(target: str) -> str:
        """
        Canonicalize a domain/hostname:
        - Strips whitespace & lowercases
        - Strips protocol (http://, https://)
        - Strips default web ports (:80, :443)
        - Strips trailing DNS dots (example.com. -> example.com)
        """
        target = target.strip().lower()

        # Strip protocol
        if target.startswith("http://"):
            target = target[7:]
        elif target.startswith("https://"):
            target = target[8:]

        # Handle wildcards
        is_wildcard = target.startswith("*.")
        if is_wildcard:
            target = target[2:]

        # Strip default ports
        if target.endswith(":80"):
            target = target[:-3]
        elif target.endswith(":443"):
            target = target[:-4]

        # Strip trailing dot
        target = target.rstrip(".")

        return f"*.{target}" if is_wildcard else target

    @staticmethod
    def _check_path(target: str) -> None:
        """Ensure the target does not contain a URL path."""
        parts = urlsplit("http://" + target)
        if parts.path and parts.path != "/":
            raise ValueError(f"Target '{target}' should not contain a path.")

    @staticmethod
    def _check_wildcard(target: str) -> None:
        """Validate wildcard placement."""
        if "*" not in target:
            return

        if not target.startswith("*."):
            raise ValueError(f"Target '{target}' has an invalid wildcard placement.")

        if target.count("*") > 1:
            raise ValueError(f"Target '{target}' should contain only one wildcard.")

    @staticmethod
    def _check_domain(target: str) -> None:
        """Validate the domain syntax."""
        domain = target[2:] if target.startswith("*.") else target

        # Reject any remaining non-standard ports (e.g. example.com:8080 is not a domain)
        if ":" in domain:
            raise ValueError(f"Target '{target}' should not contain a port number.")

        if not DomainValidator._is_valid_domain(domain):
            raise ValueError(f"Target '{target}' is not a valid domain.")

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Validate a hostname using standard RFC domain pattern."""
        if len(domain) > 253 or not domain:
            return False

        pattern = re.compile(
            r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )
        return pattern.fullmatch(domain) is not None

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
        """
        Canonicalize an HTTP/HTTPS URL for deduplication:
        - Strips fragments (#hash)
        - Lowercases scheme and netloc
        - Strips default ports (:80 for http, :443 for https)
        - Strips trailing DNS dots from hostname
        - Alphabetically sorts query parameters
        - Ensures standard root path
        """
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        netloc = parts.netloc.lower()

        # Handle port & trailing dot in netloc
        if ":" in netloc:
            host, port_str = netloc.rsplit(":", 1)
            host = host.rstrip(".")
            if (scheme == "http" and port_str == "80") or (scheme == "https" and port_str == "443"):
                netloc = host
            else:
                netloc = f"{host}:{port_str}"
        else:
            netloc = netloc.rstrip(".")

        # Normalize path
        path = parts.path or "/"
        path = re.sub(r"/{2,}", "/", path)

        # Sort query parameters alphabetically
        query = ""
        if parts.query:
            params = parse_qsl(parts.query, keep_blank_values=True)
            params.sort(key=lambda x: (x[0], x[1]))
            query = urlencode(params)

        # Rebuild without fragment
        return urlunsplit((scheme, netloc, path, query, ""))

class ScopeEvaluator:
    """
    Evaluates whether discovered hosts or URLs are in-scope or out-of-scope.
    Strictly enforces deny-over-allow precedence and wildcard boundaries.
    """

    def __init__(self, in_scope: list[str], out_of_scope: list[str] | None = None):
        self.in_scope = [DomainValidator.canonicalize(t) for t in in_scope if t.strip()]
        self.out_of_scope = [
            DomainValidator.canonicalize(t) for t in (out_of_scope or []) if t.strip()
        ]

    @staticmethod
    def match_pattern(target: str, pattern: str) -> bool:
        """
        Check if target matches a domain pattern.
        - Exact pattern ('example.com') matches 'example.com'
        - Wildcard pattern ('*.example.com') matches 'sub.example.com' and 'a.b.example.com'
        """
        target = DomainValidator.canonicalize(target)
        pattern = DomainValidator.canonicalize(pattern)

        # Exact match
        if target == pattern:
            return True

        # Wildcard match (*.example.com)
        if pattern.startswith("*."):
            base_domain = pattern[2:]
            # Target must end with '.base_domain' (e.g. '.example.com')
            return target.endswith("." + base_domain)

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

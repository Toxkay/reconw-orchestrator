import re
from urllib.parse import urlsplit

class DomainValidator:
    @staticmethod
    def validate(target: str) -> str:
        """
        Normalize and validate a domain target.
        Returns the normalized target or raises ValueError.
        """
        target = DomainValidator._normalize(target)

        DomainValidator._check_path(target)
        DomainValidator._check_port(target)
        DomainValidator._check_wildcard(target)
        DomainValidator._check_domain(target)

        return target

    @staticmethod
    def _normalize(target: str) -> str:
        """Normalize the target."""
        target = target.strip().lower()

        if target.startswith("http://"):
            target = target.removeprefix("http://")

        elif target.startswith("https://"):
            target = target.removeprefix("https://")

        return target

    @staticmethod
    def _check_path(target: str) -> None:
        """Ensure the target does not contain a URL path."""
        parts = urlsplit("http://" + target)

        if parts.path and parts.path != "/":
            raise ValueError(
                f"Target '{target}' should not contain a path."
            )

    @staticmethod
    def _check_port(target: str) -> None:
        """Ensure the target does not contain a port."""
        parts = urlsplit("http://" + target)

        if parts.port is not None:
            raise ValueError(
                f"Target '{target}' should not contain a port number."
            )

    @staticmethod
    def _check_wildcard(target: str) -> None:
        """Validate wildcard placement."""
        if "*" not in target:
            return

        if not target.startswith("*."):
            raise ValueError(
                f"Target '{target}' has an invalid wildcard placement."
            )

        if target.count("*") > 1:
            raise ValueError(
                f"Target '{target}' should contain only one wildcard."
            )

    @staticmethod
    def _check_domain(target: str) -> None:
        """Validate the domain syntax."""
        domain = target[2:] if target.startswith("*.") else target

        if not DomainValidator._is_valid_domain(domain):
            raise ValueError(
                f"Target '{target}' is not a valid domain."
            )

    @staticmethod
    def _is_valid_domain(domain: str) -> bool:
        """Validate a hostname using a local domain pattern."""
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
                print(f"[WARNING] Duplicate target removed: {target}")
                continue

            seen.add(target)
            result.append(target)

        return result
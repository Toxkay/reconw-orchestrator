from dataclasses import dataclass
from pathlib import Path

from reconw.scope.loader import load_targets
from reconw.scope.validator import DomainValidator


@dataclass(slots=True)
class ReconTargets:
    in_scope: list[str]
    out_of_scope: list[str]


def _validate_targets(targets: list[str]) -> list[str]:
    validated_targets: list[str] = []

    for target in targets:
        validated_target = DomainValidator.validate(target)
        validated_targets.append(validated_target)

    return DomainValidator.remove_duplicates(validated_targets)


def build_targets(in_scope_file: Path, out_of_scope_file: Path) -> ReconTargets:
    """Load and validate scope files into normalized target lists."""
    in_targets = _validate_targets(load_targets(in_scope_file))
    out_targets = _validate_targets(load_targets(out_of_scope_file))
    return ReconTargets(in_scope=in_targets, out_of_scope=out_targets)
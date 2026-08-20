import pytest
from pathlib import Path

from reconw.scope.loader import load_targets
from reconw.scope.validator import DomainValidator, ScopeEvaluator, URLValidator


def test_domain_validator_normalization():
    assert DomainValidator.validate("  HTTPS://Example.Com:443  ") == "example.com"
    assert DomainValidator.validate("*.SUB.Example.COM") == "*.sub.example.com"
    assert DomainValidator.validate("test.org.") == "test.org"


def test_domain_validator_rejects_paths_and_ports():
    with pytest.raises(ValueError, match="should not contain a path"):
        DomainValidator.validate("example.com/api/v1")

    with pytest.raises(ValueError, match="should not contain a port number"):
        DomainValidator.validate("example.com:8080")

    with pytest.raises(ValueError, match="invalid wildcard"):
        DomainValidator.validate("sub.*.example.com")


def test_scope_evaluator_wildcards_and_precedence():
    in_scope = ["example.com", "*.example.com", "target.org"]
    out_of_scope = ["blog.example.com", "*.staging.example.com"]

    evaluator = ScopeEvaluator(in_scope=in_scope, out_of_scope=out_of_scope)

    assert evaluator.is_in_scope("example.com") is True
    assert evaluator.is_in_scope("api.example.com") is True
    assert evaluator.is_in_scope("dev.sub.example.com") is True
    assert evaluator.is_in_scope("target.org") is True

    assert evaluator.is_in_scope("blog.example.com") is False
    assert evaluator.is_in_scope("api.staging.example.com") is False
    assert evaluator.is_in_scope("unauthorized.com") is False


def test_load_targets_file(tmp_path: Path):
    sample_file = tmp_path / "targets.txt"
    sample_file.write_text("# Comment line\nexample.com\n\n  *.example.com  \n# Another comment\n", encoding="utf-8")

    loaded = load_targets(sample_file)
    assert loaded == ["example.com", "*.example.com"]

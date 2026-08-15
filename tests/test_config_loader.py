"""
tests/test_config_loader.py
=============================
Tests for config_loader — YAML loading and JSON Schema validation.
"""

import pytest
import yaml
from pathlib import Path

from llm08_scanner.input_layer.config_loader import (
    load_config,
    validate_config,
    ConfigValidationError,
    ScannerConfig
)


def test_load_valid_config_example():
    """Load config.example.yaml -> ScannerConfig object, assert no exceptions."""
    config = load_config("config/config.example.yaml")
    assert isinstance(config, ScannerConfig)
    assert config.vector_db.type == "qdrant"
    assert config.embedding.dimension == 384
    assert len(config.tenants) == 2


def test_valid_config_has_correct_types():
    """Assert ScannerConfig fields have correct Python types after loading."""
    config = load_config("config/config.example.yaml")
    assert isinstance(config.vector_db.port, int)
    assert isinstance(config.vector_db.tls, bool)
    assert isinstance(config.thresholds.mahalanobis_sigma, float)
    assert isinstance(config.acl_rules, list)


def test_broken_fixture_loads_without_schema_error():
    """tenant_isolation_broken.yaml is syntactically valid YAML (broken at security level)."""
    config = load_config("config/test_fixtures/tenant_isolation_broken.yaml")
    # Both tenants share the same collection in this fixture
    assert config.tenants[0].collection == config.tenants[1].collection


def test_missing_required_field_raises_error(tmp_path: Path):
    """Config missing 'scanner.tenants' -> ConfigValidationError."""
    invalid_yaml = tmp_path / "invalid.yaml"
    invalid_yaml.write_text("scanner:\n  vector_db:\n    type: qdrant\n")
    with pytest.raises(ConfigValidationError) as exc:
        load_config(invalid_yaml)
    assert "required" in str(exc.value).lower()


def test_invalid_db_type_raises_error():
    """vector_db.type = 'mongo' -> ConfigValidationError."""
    with open("config/config.example.yaml", "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    
    raw["scanner"]["vector_db"]["type"] = "mongo"
    
    with pytest.raises(ConfigValidationError) as exc:
        validate_config(raw)
    assert "mongo" in str(exc.value)


def test_dimension_mismatch_caught_by_validator():
    """embedding.dimension set to string -> ConfigValidationError."""
    with open("config/config.example.yaml", "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    
    raw["scanner"]["embedding"]["dimension"] = "384"  # should be int
    
    with pytest.raises(ConfigValidationError) as exc:
        validate_config(raw)
    assert "dimension" in str(exc.value).lower() or "not of type 'integer'" in str(exc.value).lower()

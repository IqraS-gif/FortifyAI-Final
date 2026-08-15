"""
llm08_scanner.input_layer.config_loader
========================================
Loads and validates the scanner configuration from a YAML file.

Validation is performed against config/config.schema.json using jsonschema
(draft-07) before any scan operation begins. Any schema violation raises
a ConfigValidationError with a human-readable message.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError


class ConfigValidationError(Exception):
    """Raised when the config YAML fails JSON Schema validation or manual checks."""
    pass


@dataclass
class VectorDBConfig:
    type: str
    host: str
    port: int
    grpc_port: int | None
    api_key: str | None
    tls: bool
    timeout_seconds: float


@dataclass
class EmbeddingConfig:
    model: str
    device: str
    dimension: int
    batch_size: int
    normalize: bool


@dataclass
class TenantConfig:
    name: str
    collection: str
    token: str | None
    description: str | None


@dataclass
class ACLRuleConfig:
    tenant: str
    allowed_fields: list[str]
    denied_fields: list[str]
    ip_allowlist: list[str]


@dataclass
class ScoringWeights:
    acl_fuzzer: float
    inversion: float
    poisoning: float
    drift: float
    probe: float


@dataclass
class ThresholdConfig:
    collision_threshold: float
    mahalanobis_sigma: float
    dp_epsilon: float
    poisoning_top_k: int
    probe_neighbor_k: int
    isolation_forest_contamination: float | str


@dataclass
class OutputConfig:
    report_dir: str
    heatmap_dir: str
    raw_json_dir: str
    generate_pdf: bool
    generate_heatmap: bool
    timestamp_format: str


@dataclass
class ScannerConfig:
    vector_db: VectorDBConfig
    embedding: EmbeddingConfig
    tenants: list[TenantConfig]
    acl_rules: list[ACLRuleConfig]
    scoring_weights: ScoringWeights
    thresholds: ThresholdConfig
    probe_payloads: dict[str, Any]
    output: OutputConfig
    _raw_config: dict[str, Any] = field(default_factory=dict, repr=False)


def _load_schema() -> dict[str, Any]:
    """Load the JSON schema from disk."""
    schema_path = Path(__file__).parent.parent.parent / "config" / "config.schema.json"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file missing: {schema_path}")
    with open(schema_path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_config(raw_config: dict[str, Any]) -> None:
    """Validate a raw configuration dict against the JSON Schema."""
    schema = _load_schema()
    try:
        validate(instance=raw_config, schema=schema)
    except ValidationError as e:
        # Provide a more human-readable error path
        path = " -> ".join(str(p) for p in e.absolute_path)
        msg = f"Configuration error at [{path}]: {e.message}" if path else f"Configuration error: {e.message}"
        raise ConfigValidationError(msg) from e


def load_config(path: str | Path) -> ScannerConfig:
    """Load, validate, and parse a YAML configuration file into a ScannerConfig object."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file missing: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        try:
            raw_data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML format: {e}") from e

    if raw_data is None:
        raise ConfigValidationError("Config file is empty")

    # Validate against JSON schema
    validate_config(raw_data)

    c = raw_data["scanner"]

    # Map to dataclasses
    vector_db = VectorDBConfig(**c["vector_db"])
    embedding = EmbeddingConfig(**c["embedding"])
    
    tenants = [TenantConfig(**t) for t in c["tenants"]]
    acl_rules = [ACLRuleConfig(**r) for r in c.get("acl_rules", [])]
    
    scoring_weights = ScoringWeights(**c["scoring_weights"])
    thresholds = ThresholdConfig(**c["thresholds"])
    
    output = OutputConfig(**c["output"])
    probe_payloads = c.get("probe_payloads", {})

    return ScannerConfig(
        vector_db=vector_db,
        embedding=embedding,
        tenants=tenants,
        acl_rules=acl_rules,
        scoring_weights=scoring_weights,
        thresholds=thresholds,
        probe_payloads=probe_payloads,
        output=output,
        _raw_config=c,
    )

"""
llm08_scanner.core.scoring_engine
====================================
Phase 5 — Aggregated Risk Scoring Engine.

Aggregates ModuleResult outputs from all scanner modules into a single
risk score and risk level, weighted by the configured scoring_weights.

Risk level mapping:
    80–100: CRITICAL
    60–79:  HIGH
    40–59:  MEDIUM
    20–39:  LOW
    0–19:   INFO

Weighting contract:
    Weights must sum to 1.0 ± 1e-6.
    ScoringEngine raises ConfigurationError if they do not — it will NOT
    silently normalise, as that would hide misconfigured configs.
"""

from __future__ import annotations

import datetime
from datetime import timezone
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModuleResult:
    """Standard output dataclass for every scanner module."""

    module_name: str
    severity: str          # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    score: float           # 0.0 – 100.0
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: float = 0.0
    error: str | None = None


@dataclass
class OverallRiskScore:
    """Aggregated output from the ScoringEngine."""

    overall_score: float
    risk_level: str                       # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    module_results: list[ModuleResult]
    scan_timestamp: str                   # ISO-8601 UTC
    config_snapshot: dict[str, Any]
    scanner_version: str
    weights: dict[str, float] = field(default_factory=dict)


class ConfigurationError(ValueError):
    """Raised when ScoringEngine is given an invalid weight configuration."""


class ScoringEngine:
    """Weighted aggregator for all module results."""

    SCANNER_VERSION = "0.5.0"

    def __init__(self, weights: dict[str, float]) -> None:
        """
        Args:
            weights: Dict mapping module_name → float (must sum to 1.0 ± 1e-6).

        Raises:
            ConfigurationError: If weights do not sum to 1.0.
        """
        total = sum(weights.values())
        if abs(total - 1.0) > 1e-6:
            raise ConfigurationError(
                f"Scoring weights must sum to 1.0, got {total:.6f}. "
                "Adjust your config.scoring_weights."
            )
        self._weights = weights

    def aggregate(
        self,
        module_results: list[ModuleResult],
        config_snapshot: dict[str, Any] | None = None,
    ) -> OverallRiskScore:
        """
        Compute a weighted-average overall risk score.

        Modules not listed in weights are treated as weight=0.
        Modules listed in weights but absent from results contribute 0 to the sum.
        """
        weighted_sum = 0.0
        for result in module_results:
            w = self._weights.get(result.module_name, 0.0)
            weighted_sum += result.score * w

        # Normalise by the total weight of modules that actually ran
        covered_weight = sum(
            self._weights.get(r.module_name, 0.0) for r in module_results
        )
        if covered_weight > 0:
            overall = weighted_sum / covered_weight
        else:
            overall = 0.0

        overall = min(max(overall, 0.0), 100.0)

        return OverallRiskScore(
            overall_score=overall,
            risk_level=self.score_to_risk_level(overall),
            module_results=module_results,
            scan_timestamp=datetime.datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%f%z"),
            config_snapshot=config_snapshot or {},
            scanner_version=self.SCANNER_VERSION,
            weights=self._weights,
        )

    @staticmethod
    def score_to_risk_level(score: float) -> str:
        """Map 0–100 score to risk level string."""
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFO"

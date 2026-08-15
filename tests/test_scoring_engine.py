"""
tests/test_scoring_engine.py
==============================
Phase 5 — ScoringEngine tests.

Tests:
  1. Weighted aggregation produces the expected score.
  2. Weight-sum enforcement raises ConfigurationError if not 1.0.
  3. score_to_risk_level boundary checks (all five tiers).
  4. Known-outlier fixture → CRITICAL/HIGH; clean fixture → LOW/INFO.
  5. Partial module coverage: only a subset of modules ran; score is
     normalised to the weight of modules that ran (not penalised for
     modules that didn't execute).
"""

from __future__ import annotations

import pytest

from llm08_scanner.core.scoring_engine import (
    ConfigurationError,
    ModuleResult,
    OverallRiskScore,
    ScoringEngine,
)

WEIGHTS = {
    "acl_fuzzer": 0.30,
    "inversion":  0.20,
    "poisoning":  0.25,
    "drift":      0.15,
    "probe":      0.10,
}


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_result(module: str, score: float) -> ModuleResult:
    return ModuleResult(
        module_name=module,
        severity=ScoringEngine.score_to_risk_level(score),
        score=score,
    )


# ── weight enforcement ────────────────────────────────────────────────────────

def test_weights_must_sum_to_one():
    """ScoringEngine raises ConfigurationError when weights don't sum to 1.0."""
    with pytest.raises(ConfigurationError):
        ScoringEngine({"acl_fuzzer": 0.50, "inversion": 0.30})   # sums to 0.80


def test_weights_exact_one_accepted():
    """ScoringEngine accepts weights that sum to exactly 1.0."""
    ScoringEngine(WEIGHTS)   # must not raise


# ── score_to_risk_level boundaries ───────────────────────────────────────────

@pytest.mark.parametrize("score,expected", [
    (100.0, "CRITICAL"),
    (80.0,  "CRITICAL"),
    (79.9,  "HIGH"),
    (60.0,  "HIGH"),
    (59.9,  "MEDIUM"),
    (40.0,  "MEDIUM"),
    (39.9,  "LOW"),
    (20.0,  "LOW"),
    (19.9,  "INFO"),
    (0.0,   "INFO"),
])
def test_risk_level_boundaries(score, expected):
    assert ScoringEngine.score_to_risk_level(score) == expected


# ── weighted aggregation correctness ─────────────────────────────────────────

def test_weighted_average_is_correct():
    """
    Scores: acl=80, inversion=60, poisoning=40, drift=20, probe=0.
    Weighted sum:
      80×0.30 + 60×0.20 + 40×0.25 + 20×0.15 + 0×0.10
      = 24 + 12 + 10 + 3 + 0 = 49.0
    """
    engine = ScoringEngine(WEIGHTS)
    results = [
        _make_result("acl_fuzzer", 80.0),
        _make_result("inversion",  60.0),
        _make_result("poisoning",  40.0),
        _make_result("drift",      20.0),
        _make_result("probe",       0.0),
    ]
    overall: OverallRiskScore = engine.aggregate(results)
    assert abs(overall.overall_score - 49.0) < 0.01
    assert overall.risk_level == "MEDIUM"


# ── partial module coverage normalisation ─────────────────────────────────────

def test_partial_coverage_normalisation():
    """
    Only acl_fuzzer (w=0.30) and poisoning (w=0.25) ran.
    Covered weight = 0.55.
    acl score=90, poisoning score=50.
    Expected: (90*0.30 + 50*0.25) / 0.55 = (27 + 12.5) / 0.55 ≈ 71.8 (HIGH).
    """
    engine = ScoringEngine(WEIGHTS)
    results = [
        _make_result("acl_fuzzer", 90.0),
        _make_result("poisoning",  50.0),
    ]
    overall = engine.aggregate(results)
    assert abs(overall.overall_score - 71.818) < 0.1
    assert overall.risk_level == "HIGH"


# ── known-outlier (CRITICAL) vs clean (INFO) fixture ─────────────────────────

def test_critical_fixture_scores_critical():
    """All modules report high scores → overall must be CRITICAL."""
    engine = ScoringEngine(WEIGHTS)
    results = [
        _make_result("acl_fuzzer", 95.0),
        _make_result("inversion",  90.0),
        _make_result("poisoning",  85.0),
        _make_result("drift",      80.0),
        _make_result("probe",      75.0),
    ]
    overall = engine.aggregate(results)
    assert overall.risk_level == "CRITICAL"
    assert overall.overall_score >= 80.0


def test_clean_fixture_scores_low_or_info():
    """All modules report zero/near-zero scores → overall must be LOW or INFO."""
    engine = ScoringEngine(WEIGHTS)
    results = [
        _make_result("acl_fuzzer", 0.0),
        _make_result("inversion",  5.0),
        _make_result("poisoning",  0.0),
        _make_result("drift",      2.0),
        _make_result("probe",      0.0),
    ]
    overall = engine.aggregate(results)
    assert overall.risk_level in ("LOW", "INFO")
    assert overall.overall_score < 20.0


# ── OverallRiskScore fields ───────────────────────────────────────────────────

def test_overall_result_has_required_fields():
    """OverallRiskScore must contain scan_timestamp, scanner_version, module_results."""
    engine = ScoringEngine(WEIGHTS)
    results = [_make_result("acl_fuzzer", 50.0)]
    overall = engine.aggregate(results, config_snapshot={"test": True})

    assert overall.scan_timestamp.endswith("Z") or "+00:00" in overall.scan_timestamp
    assert overall.scanner_version == ScoringEngine.SCANNER_VERSION
    assert len(overall.module_results) == 1
    assert overall.config_snapshot == {"test": True}

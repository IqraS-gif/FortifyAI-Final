"""
tests/test_drift_detector.py
==============================
Phase 5 — DriftDetector tests.

Positive case: inject a deliberate outlier vector far from the cluster
centroid and confirm it is flagged (Mahalanobis > threshold).

Negative case: all vectors drawn from the same distribution — confirm
false-positive rate is low (≤ sigma_threshold % flagged is acceptable
for a 3σ rule in a normal distribution).
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.core.drift_detector import DriftDetector, DriftResult
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord

DIM = 32   # larger than Phase 2-3 tests so Mahalanobis has a meaningful covariance


@pytest.fixture(scope="module")
def adapter():
    a = QdrantAdapter(
        host="127.0.0.1", port=6333, grpc_port=None,
        api_key=None, tls=False, timeout=5.0
    )
    a.connect()
    if not a.health_check():
        pytest.skip("Qdrant not running on 127.0.0.1:6333")
    return a


@pytest.fixture
def clean_namespace(adapter):
    ns = "drift_clean_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)
    yield ns
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)


@pytest.fixture
def outlier_namespace(adapter):
    ns = "drift_outlier_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)
    yield ns
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)


def _unit(vec: np.ndarray) -> list[float]:
    norm = np.linalg.norm(vec)
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


# ── POSITIVE CASE: injected outlier must be flagged ──────────────────────────

def test_outlier_is_detected(adapter, outlier_namespace):
    """
    Positive case: 20 clean vectors clustered tightly around the origin,
    plus 1 deliberate outlier pointing in the opposite direction.
    The outlier must appear in the DriftResult with is_outlier=True.
    """
    rng = np.random.default_rng(seed=42)

    # 20 clean vectors: small perturbations around a fixed centroid
    centroid = np.ones(DIM, dtype=float)
    records = []
    for i in range(20):
        vec = centroid + rng.normal(scale=0.05, size=DIM)
        records.append(VectorRecord(id=i, vector=_unit(vec), namespace=outlier_namespace, payload={}))

    # 1 outlier: points in the exact opposite direction
    outlier_vec = -centroid + rng.normal(scale=0.01, size=DIM)
    outlier_id = 999
    records.append(VectorRecord(id=outlier_id, vector=_unit(outlier_vec),
                                namespace=outlier_namespace, payload={}))

    adapter.upsert(records, outlier_namespace)

    detector = DriftDetector(
        adapter=adapter,
        namespaces=[outlier_namespace],
        sigma_threshold=2.5,
        dbscan_eps=0.20,
        dbscan_min_samples=2,
    )
    result: DriftResult = detector.run()

    outlier_findings = [f for f in result.findings if f.vector_id == outlier_id and f.is_outlier]
    assert len(outlier_findings) == 1, (
        f"Expected outlier id={outlier_id} to be flagged. "
        f"Findings: {[(f.vector_id, f.is_outlier, f.mahalanobis_distance) for f in result.findings]}"
    )
    assert result.score > 0.0


# ── NEGATIVE CASE: clean distribution should have low outlier rate ────────────

def test_clean_namespace_low_false_positive_rate(adapter, clean_namespace):
    """
    Negative case: 30 vectors all drawn from the same Gaussian.
    At 3σ, ≤0.3% of a normal distribution should be flagged.
    We allow up to 10% here (3/30) to account for small-sample variance.
    """
    rng = np.random.default_rng(seed=7)
    n = 30
    records = []
    for i in range(n):
        vec = rng.normal(loc=0.5, scale=0.08, size=DIM)
        records.append(VectorRecord(id=i, vector=_unit(vec), namespace=clean_namespace, payload={}))

    adapter.upsert(records, clean_namespace)

    detector = DriftDetector(
        adapter=adapter,
        namespaces=[clean_namespace],
        sigma_threshold=3.0,
        dbscan_eps=0.20,
        dbscan_min_samples=2,
    )
    result: DriftResult = detector.run()

    outlier_count = sum(1 for f in result.findings if f.is_outlier)
    false_positive_rate = outlier_count / n
    assert false_positive_rate <= 0.10, (
        f"False-positive rate {false_positive_rate:.1%} exceeds 10% on clean distribution "
        f"({outlier_count}/{n} flagged)"
    )

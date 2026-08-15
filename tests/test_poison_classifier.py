"""
tests/test_poison_classifier.py
=================================
Phase 6 — PoisonClassifier tests.

Positive case: Outlier injected -> flagged.
Negative case: < 50 samples -> skipped.
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.unique_tech.poison_classifier import PoisonClassifier, PoisonClassifierResult
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord

DIM = 16


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


def _unit(vec: np.ndarray) -> list[float]:
    norm = np.linalg.norm(vec)
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


def test_poison_classifier_detects_outlier(adapter):
    ns = "pc_detect_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)

    # Need >= 50 for it to run. Let's do 60 clean, 2 outliers.
    rng = np.random.default_rng(42)
    centroid = np.ones(DIM)
    
    records = []
    for i in range(60):
        vec = centroid + rng.normal(scale=0.1, size=DIM)
        records.append(VectorRecord(id=i, vector=_unit(vec), namespace=ns))
        
    outlier_vec = -centroid + rng.normal(scale=0.01, size=DIM)
    records.append(VectorRecord(id=9998, vector=_unit(outlier_vec), namespace=ns))
    records.append(VectorRecord(id=9999, vector=_unit(outlier_vec * 0.9), namespace=ns))
    
    adapter.upsert(records, ns)
    
    clf = PoisonClassifier(adapter=adapter, namespaces=[ns], contamination=0.05)
    result: PoisonClassifierResult = clf.run()
    
    assert len(result.findings) == 62
    
    flagged = [f for f in result.findings if f.is_anomalous]
    flagged_ids = {f.record_id for f in flagged}
    
    # Should flag our outliers
    assert 9998 in flagged_ids
    assert 9999 in flagged_ids
    assert result.score > 0.0

    adapter._client.delete_collection(ns)


def test_poison_classifier_skips_small(adapter):
    ns = "pc_skip_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)

    rng = np.random.default_rng(42)
    records = []
    for i in range(10): # < 50
        vec = rng.normal(size=DIM)
        records.append(VectorRecord(id=i, vector=_unit(vec), namespace=ns))
        
    adapter.upsert(records, ns)
    
    clf = PoisonClassifier(adapter=adapter, namespaces=[ns])
    result: PoisonClassifierResult = clf.run()
    
    assert result.score == 0.0
    assert len(result.findings) == 0
    assert ns in result.evidence["namespaces_skipped"]

    adapter._client.delete_collection(ns)

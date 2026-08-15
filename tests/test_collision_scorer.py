"""
tests/test_collision_scorer.py
================================
Phase 6 — CollisionScorer tests.

Positive case: Identical vector in two namespaces -> detected.
Negative case: Orthogonal vectors -> not detected.
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.unique_tech.collision_scorer import CollisionScorer, CollisionResult
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


def dummy_embed(text: str) -> list[float]:
    np.random.seed(abs(hash(text)) % (2 ** 32))
    vec = np.random.randn(DIM).astype(float)
    norm = float(np.linalg.norm(vec))
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


def test_collision_scorer_detects_collision(adapter):
    ns_a = "coll_a"
    ns_b = "coll_b"
    
    for ns in [ns_a, ns_b]:
        if ns in adapter.list_namespaces():
            adapter._client.delete_collection(ns)
        adapter.create_namespace(ns, DIM)

    # Identical vector in both
    vec = dummy_embed("collision_target")
    adapter.upsert([VectorRecord(id=1, vector=vec, namespace=ns_a)], ns_a)
    adapter.upsert([VectorRecord(id=1, vector=vec, namespace=ns_b)], ns_b)

    scorer = CollisionScorer(adapter=adapter, namespaces=[ns_a, ns_b], embed_fn=dummy_embed, threshold=0.98)
    result: CollisionResult = scorer.run()

    assert len(result.findings) == 1
    assert result.findings[0].similarity >= 0.98
    assert result.score > 0.0

    for ns in [ns_a, ns_b]:
        adapter._client.delete_collection(ns)


def test_collision_scorer_clean(adapter):
    ns_a = "coll_clean_a"
    ns_b = "coll_clean_b"
    
    for ns in [ns_a, ns_b]:
        if ns in adapter.list_namespaces():
            adapter._client.delete_collection(ns)
        adapter.create_namespace(ns, DIM)

    # Different vectors
    adapter.upsert([VectorRecord(id=1, vector=dummy_embed("random1"), namespace=ns_a)], ns_a)
    adapter.upsert([VectorRecord(id=1, vector=dummy_embed("random2"), namespace=ns_b)], ns_b)

    scorer = CollisionScorer(adapter=adapter, namespaces=[ns_a, ns_b], embed_fn=dummy_embed, threshold=0.98)
    result: CollisionResult = scorer.run()

    assert len(result.findings) == 0
    assert result.score == 0.0

    for ns in [ns_a, ns_b]:
        adapter._client.delete_collection(ns)

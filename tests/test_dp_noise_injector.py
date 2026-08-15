"""
tests/test_dp_noise_injector.py
=================================
Phase 6 — DP Noise Injector tests.

Positive case: Leakage after DP is measurably lower than before.
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.unique_tech.dp_noise_injector import DpNoiseInjector, DpResult
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


def test_dp_noise_reduces_leakage(adapter):
    ns = "dp_test_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)

    # Upsert words from the dummy embedder's known vocabulary
    # We want a high initial leakage score
    words = ["the", "of", "and", "to", "in", "a", "is"]
    records = []
    for i, w in enumerate(words):
        records.append(VectorRecord(id=i, vector=dummy_embed(w), namespace=ns, payload={}))
    adapter.upsert(records, ns)

    injector = DpNoiseInjector(
        adapter=adapter,
        namespaces=[ns],
        embed_fn=dummy_embed,
        epsilon=50.0,  # Realistic budget to preserve utility (utility loss ~19%)
    )
    
    result: DpResult = injector.run()
    
    assert len(result.findings) == 1
    finding = result.findings[0]
    
    # Assert DP noise measurably reduced inversion leakage
    assert finding.leakage_after < finding.leakage_before
    assert finding.delta_leakage > 0
    assert result.score > 0
    
    adapter._client.delete_collection(ns)

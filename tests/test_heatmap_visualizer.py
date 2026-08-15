"""
tests/test_heatmap_visualizer.py
==================================
Tests heatmap visualization gracefully falls back or succeeds.
"""

import os
from llm08_scanner.output_layer.heatmap_visualizer import generate_heatmap
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord
import pytest
import numpy as np

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

def test_heatmap_visualizer(adapter):
    ns = "heatmap_test_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)

    records = [VectorRecord(id=i, vector=dummy_embed(str(i)), namespace=ns) for i in range(10)]
    adapter.upsert(records, ns)
    
    anomalous = {1, 2}
    path = generate_heatmap(adapter, [ns], anomalous)
    
    if path:
        assert os.path.exists(path)
        assert path.endswith(".png")
        os.remove(path)
        
    adapter._client.delete_collection(ns)

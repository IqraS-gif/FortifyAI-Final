"""
tests/test_qdrant_adapter.py
==============================
Tests for QdrantAdapter — requires a running Qdrant instance.
"""

import pytest
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord


@pytest.fixture(scope="module")
def adapter():
    """Provides a connected QdrantAdapter or skips if Qdrant is down."""
    a = QdrantAdapter(
        host="127.0.0.1",
        port=6333,
        grpc_port=None,
        api_key=None,
        tls=False,
        timeout=5.0
    )
    a.connect()
    
    if not a.health_check():
        pytest.skip("Qdrant not running on localhost:6333")
    
    yield a
    
    # Teardown: delete all test_llm08_* collections
    try:
        collections = a.list_namespaces()
        for c in collections:
            if c.startswith("test_llm08_"):
                a._client.delete_collection(c)
    except Exception:
        pass


def test_health_check_returns_true(adapter):
    assert adapter.health_check() is True


def test_create_and_list_namespace(adapter):
    ns = "test_llm08_basic"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
        
    adapter.create_namespace(ns, 384)
    assert ns in adapter.list_namespaces()


def test_upsert_and_count(adapter):
    ns = "test_llm08_upsert"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, 384)
    
    records = [
        VectorRecord(id=i, vector=[0.1]*384, namespace=ns, payload={"idx": i})
        for i in range(10)
    ]
    adapter.upsert(records, ns)
    assert adapter.count(ns) == 10


def test_query_returns_correct_top_k(adapter):
    ns = "test_llm08_query"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, 384)
    
    # 384-dim vectors
    v1 = [1.0] + [0.0]*383
    v2 = [0.0, 1.0] + [0.0]*382
    
    records = [
        VectorRecord(id=1, vector=v1, namespace=ns),
        VectorRecord(id=2, vector=v2, namespace=ns)
    ]
    adapter.upsert(records, ns)
    
    result = adapter.query(vector=v1, top_k=1, namespace=ns)
    assert result.top_k == 1
    assert len(result.records) == 1
    assert result.records[0].id == 1
    assert result.records[0].score > 0.99  # close to 1.0 cosine sim


def test_fetch_all_returns_all_records(adapter):
    ns = "test_llm08_fetch"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, 3) # smaller dim for test speed
    
    records = [
        VectorRecord(id=i, vector=[0.1, 0.2, 0.3], namespace=ns)
        for i in range(50)
    ]
    adapter.upsert(records, ns)
    
    fetched = adapter.fetch_all(ns, with_vectors=True, limit=100)
    assert len(fetched) == 50
    assert len(fetched[0].vector) == 3


def test_delete_removes_records(adapter):
    ns = "test_llm08_delete"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, 384)
    
    records = [
        VectorRecord(id=i, vector=[0.1]*384, namespace=ns)
        for i in range(5)
    ]
    adapter.upsert(records, ns)
    adapter.delete([0, 1], ns)
    assert adapter.count(ns) == 3


def test_dimension_mismatch_raises_error(adapter):
    ns = "test_llm08_dim"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, 384)
    
    records = [VectorRecord(id=1, vector=[0.1]*256, namespace=ns)]
    with pytest.raises(ValueError) as exc:
        adapter.upsert(records, ns)
    assert "Dimension" in str(exc.value) or "mismatch" in str(exc.value).lower()

"""
tests/test_inversion_tester.py
================================
Tests for InversionTester.
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.core.inversion_tester import InversionTester
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord

DIM = 16


@pytest.fixture(scope="module")
def adapter():
    a = QdrantAdapter(host="127.0.0.1", port=6333, grpc_port=None, api_key=None, tls=False, timeout=5.0)
    a.connect()
    if not a.health_check():
        pytest.skip("Qdrant not running on 127.0.0.1:6333")
    return a


@pytest.fixture
def test_namespace(adapter):
    ns = "test_inversion_ns"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)
    yield ns
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)


def dummy_embed(text: str) -> list[float]:
    """Deterministic embedding based on text hash, matching dimension."""
    np.random.seed(abs(hash(text)) % (2**32))
    vec = np.random.randn(DIM)
    norm = np.linalg.norm(vec)
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


def test_inversion_tester_structure(adapter, test_namespace):
    # Upsert a single dummy record
    adapter.upsert(
        [VectorRecord(id=1, vector=dummy_embed("hello world"), namespace=test_namespace, payload={})],
        test_namespace
    )

    tester = InversionTester(
        adapter=adapter,
        namespaces=[test_namespace],
        embed_fn=dummy_embed,
        vocab_size=10  # small vocab for fast test
    )

    result = tester.run(sample_size=1, top_k_tokens=3)
    assert 0.0 <= result.score <= 100.0
    assert len(result.findings) == 1
    
    finding = result.findings[0]
    assert finding.vector_id == 1
    assert finding.namespace == test_namespace
    assert len(finding.top_k_tokens) == 3
    assert isinstance(finding.max_score, float)


def test_inversion_ground_truth(adapter, test_namespace):
    """
    Embed a known vocabulary word, run inversion, and confirm the word
    appears in the top candidates with high confidence.
    """
    tester = InversionTester(
        adapter=adapter,
        namespaces=[test_namespace],
        embed_fn=dummy_embed,
        vocab_size=10
    )
    # tester.vocab[0] is the most frequent word from the index
    target_word = tester.vocab[0]
    word_vec = dummy_embed(target_word)
    
    # Upsert the word vector
    adapter.upsert(
        [VectorRecord(id=101, vector=word_vec, namespace=test_namespace, payload={})],
        test_namespace
    )
    
    result = tester.run(sample_size=1, top_k_tokens=3)
    
    finding = next(f for f in result.findings if f.vector_id == 101)
    
    # Assert ground-truth word is recovered and score is very high (near 1.0)
    assert target_word in finding.top_k_tokens
    assert finding.max_score > 0.90


def test_inversion_negative_control(adapter, test_namespace):
    """
    Run inversion on a completely random high-entropy vector and confirm
    the confidence score is low.
    """
    np.random.seed(42)
    # A completely random vector not derived from any word hash
    random_vec = np.random.randn(DIM)
    norm = np.linalg.norm(random_vec)
    random_vec = (random_vec / norm).tolist()
    
    adapter.upsert(
        [VectorRecord(id=202, vector=random_vec, namespace=test_namespace, payload={})],
        test_namespace
    )
    
    tester = InversionTester(
        adapter=adapter,
        namespaces=[test_namespace],
        embed_fn=dummy_embed,
        vocab_size=100  # slightly larger to give it more false targets
    )
    
    result = tester.run(sample_size=1, top_k_tokens=3)
    finding = next(f for f in result.findings if f.vector_id == 202)
    
    # Random vectors in high dim space are nearly orthogonal to most things
    # Score shouldn't be suspiciously high
    assert finding.max_score < 0.60

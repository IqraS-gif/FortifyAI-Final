"""
tests/test_probe_generator.py
==============================
Phase 2 — ProbeGenerator + PayloadLibrary integration tests.

Tests run against a live Qdrant instance (standalone binary).
The module-level fixture skips the whole file if Qdrant is not reachable.
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord
from llm08_scanner.input_layer.payload_library import (
    AttackType,
    PayloadLibrary,
    PayloadSource,
    SEMANTIC_PROBE_SEEDS,
    ACL_BYPASS_SEEDS,
    ADVERSARIAL_PAYLOADS,
    SENSITIVE_FIELD_NAMES,
)
from llm08_scanner.core.probe_generator import (
    ProbeGenerator,
    ProbeGeneratorResult,
    _synonym_substitution,
)

DIM = 16   # small dimension keeps tests fast; ProbeGenerator is dim-agnostic

# ---------------------------------------------------------------------------
# Session fixtures
# ---------------------------------------------------------------------------


def _make_embed_fn(dim: int = DIM):
    """Return a deterministic fake embed function (no GPU required)."""
    rng = np.random.default_rng(0)
    cache: dict[str, list[float]] = {}

    def embed(text: str) -> list[float]:
        if text not in cache:
            v = rng.random(dim).astype(np.float32)
            v /= np.linalg.norm(v)
            cache[text] = v.tolist()
        return cache[text]

    return embed


@pytest.fixture(scope="module")
def adapter():
    """Shared live Qdrant adapter; skips module if server unreachable."""
    a = QdrantAdapter(host="127.0.0.1", port=6333, grpc_port=None,
                      api_key=None, tls=False, timeout=5.0)
    a.connect()
    if not a.health_check():
        pytest.skip("Qdrant not running on localhost:6333 — start with scripts/start_qdrant.ps1")
    yield a
    # cleanup
    for ns in a.list_namespaces():
        if ns.startswith("probe_test_"):
            a._client.delete_collection(ns)


@pytest.fixture(scope="module")
def two_namespaces(adapter):
    """
    Create two namespaces pre-seeded with vectors:
      - probe_test_ns_a : 20 vectors with payload tenant='a'
      - probe_test_ns_b : 20 vectors with payload tenant='b'
    """
    ns_a, ns_b = "probe_test_ns_a", "probe_test_ns_b"

    for ns in (ns_a, ns_b):
        if ns in adapter.list_namespaces():
            adapter._client.delete_collection(ns)
        adapter.create_namespace(ns, DIM)

    rng = np.random.default_rng(1)
    for ns, tenant in ((ns_a, "a"), (ns_b, "b")):
        records = [
            VectorRecord(
                id=i,
                vector=(v := rng.random(DIM).astype(np.float32) / np.linalg.norm(rng.random(DIM))).tolist(),
                namespace=ns,
                payload={"tenant": tenant, "idx": i},
            )
            for i in range(20)
        ]
        adapter.upsert(records, ns)

    return ns_a, ns_b


# ---------------------------------------------------------------------------
# PayloadLibrary unit tests (no Qdrant needed)
# ---------------------------------------------------------------------------

class TestPayloadLibrary:
    def test_built_in_seeds_are_present(self):
        """Assert PayloadLibrary ships with >=10 SEMANTIC_PROBE seeds."""
        lib = PayloadLibrary()
        seeds = lib.get_seeds(AttackType.SEMANTIC_PROBE)
        assert len(seeds) >= 10

    def test_acl_bypass_seeds_are_present(self):
        """Assert PayloadLibrary includes ACL_BYPASS seed phrases."""
        lib = PayloadLibrary()
        seeds = lib.get_seeds(AttackType.ACL_BYPASS)
        assert len(seeds) >= 3

    def test_filter_by_source(self):
        """get_seeds(source=BUILT_IN) returns only built-in entries."""
        lib = PayloadLibrary()
        built_in = lib.get_seeds(source=PayloadSource.BUILT_IN)
        assert all(s.source == PayloadSource.BUILT_IN for s in built_in)

    def test_add_user_seed_is_retrievable(self):
        """User-defined seeds appear in get_seeds with source=USER_DEFINED."""
        lib = PayloadLibrary()
        lib.add_user_seed("Custom probe phrase", AttackType.SEMANTIC_PROBE)
        user = lib.get_seeds(source=PayloadSource.USER_DEFINED)
        assert any(s.text == "Custom probe phrase" for s in user)

    def test_adversarial_payloads_present(self):
        """get_adversarial_payloads() returns >=3 built-in templates."""
        lib = PayloadLibrary()
        assert len(lib.get_adversarial_payloads()) >= 3

    def test_sensitive_fields_present(self):
        """get_sensitive_fields() includes standard PII/secret fields."""
        lib = PayloadLibrary()
        fields = lib.get_sensitive_fields()
        assert "ssn" in fields
        assert "api_key" in fields

    def test_add_sensitive_field_no_duplicate(self):
        """Adding the same field twice does not create duplicates."""
        lib = PayloadLibrary()
        lib.add_sensitive_field("custom_secret")
        lib.add_sensitive_field("custom_secret")
        assert lib.get_sensitive_fields().count("custom_secret") == 1


# ---------------------------------------------------------------------------
# Paraphrase helper unit tests (no Qdrant needed)
# ---------------------------------------------------------------------------

class TestSynonymSubstitution:
    def test_returns_list_of_strings(self):
        variants = _synonym_substitution("What is the company policy?", n_variants=3)
        assert isinstance(variants, list)
        assert all(isinstance(v, str) for v in variants)

    def test_returns_up_to_n_variants(self):
        variants = _synonym_substitution("Show me internal financial data.", n_variants=4)
        assert len(variants) <= 4

    def test_variants_are_unique(self):
        variants = _synonym_substitution("What are the internal financial projections?", n_variants=4)
        assert len(variants) == len(set(variants))

    def test_deterministic_with_same_seed(self):
        v1 = _synonym_substitution("Company policy for HR.", n_variants=3, seed=0)
        v2 = _synonym_substitution("Company policy for HR.", n_variants=3, seed=0)
        assert v1 == v2

    def test_different_seeds_may_differ(self):
        v1 = _synonym_substitution("Company policy for HR.", n_variants=3, seed=0)
        v2 = _synonym_substitution("Company policy for HR.", n_variants=3, seed=99)
        # Not guaranteed to differ, but usually will — this is a soft check
        # (deterministic test above is the hard correctness check)
        assert isinstance(v2, list)


# ---------------------------------------------------------------------------
# ProbeGenerator integration tests (live Qdrant required)
# ---------------------------------------------------------------------------

class TestProbeGeneratorLive:
    def test_run_returns_probe_generator_result(self, adapter, two_namespaces):
        """ProbeGenerator.run() returns a ProbeGeneratorResult with expected fields."""
        ns_a, ns_b = two_namespaces
        lib = PayloadLibrary()
        gen = ProbeGenerator(
            adapter=adapter,
            namespaces=[ns_a, ns_b],
            embed_fn=_make_embed_fn(DIM),
            payload_library=lib,
            top_k=3,
            n_paraphrases=2,
        )
        result = gen.run()
        assert isinstance(result, ProbeGeneratorResult)
        assert result.total_probes > 0
        assert 0.0 <= result.score <= 1.0

    def test_score_is_fraction_of_cross_namespace_hits(self, adapter, two_namespaces):
        """score == cross_namespace_count / total_probes."""
        ns_a, ns_b = two_namespaces
        gen = ProbeGenerator(
            adapter=adapter,
            namespaces=[ns_a, ns_b],
            embed_fn=_make_embed_fn(DIM),
            top_k=3,
            n_paraphrases=2,
        )
        result = gen.run()
        if result.total_probes > 0:
            expected = result.cross_namespace_count / result.total_probes
            assert abs(result.score - expected) < 1e-9

    def test_single_namespace_no_cross_hits(self, adapter):
        """With only one namespace, cross-namespace score must be 0.0."""
        ns = "probe_test_single"
        if ns in adapter.list_namespaces():
            adapter._client.delete_collection(ns)
        adapter.create_namespace(ns, DIM)
        rng = np.random.default_rng(5)
        records = [
            VectorRecord(id=i, vector=(v := rng.random(DIM)).tolist(), namespace=ns)
            for i in range(10)
        ]
        adapter.upsert(records, ns)

        gen = ProbeGenerator(
            adapter=adapter,
            namespaces=[ns],
            embed_fn=_make_embed_fn(DIM),
            top_k=3,
            n_paraphrases=2,
        )
        result = gen.run()
        assert result.score == 0.0, "Single namespace must never produce cross-namespace hits"

    def test_generate_paraphrases_returns_strings(self, adapter, two_namespaces):
        """generate_paraphrases() returns a non-empty list of strings."""
        ns_a, ns_b = two_namespaces
        gen = ProbeGenerator(
            adapter=adapter,
            namespaces=[ns_a, ns_b],
            embed_fn=_make_embed_fn(DIM),
            top_k=3,
            n_paraphrases=3,
        )
        paraphrases = gen.generate_paraphrases("What are the internal company projections?")
        assert len(paraphrases) > 0
        assert all(isinstance(p, str) for p in paraphrases)

    def test_findings_structure_is_correct(self, adapter, two_namespaces):
        """Each finding dict contains required keys."""
        ns_a, ns_b = two_namespaces
        gen = ProbeGenerator(
            adapter=adapter,
            namespaces=[ns_a, ns_b],
            embed_fn=_make_embed_fn(DIM),
            top_k=3,
            n_paraphrases=2,
        )
        result = gen.run()
        for finding in result.findings:
            assert "probe_text" in finding
            assert "origin_namespace" in finding
            assert "cross_namespace_hits" in finding
            assert "top_cross_score" in finding

    def test_real_embedder_semantic_geometry(self, adapter):
        """
        Verify that using a REAL embedding model correctly preserves
        semantic geometry to catch a cross-namespace leakage attack.
        """
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            pytest.skip("sentence-transformers not installed")

        # Load the actual Phase 0 chosen model
        model = SentenceTransformer("all-MiniLM-L6-v2")
        real_dim = 384
        
        def real_embed_fn(text: str) -> list[float]:
            return model.encode(text).tolist()

        # Set up a target namespace representing a highly sensitive vault
        target_ns = "probe_test_real_target"
        if target_ns in adapter.list_namespaces():
            adapter._client.delete_collection(target_ns)
        adapter.create_namespace(target_ns, real_dim)

        # Insert a sensitive document
        sensitive_text = "The CEO's exact compensation package is $1,500,000 base plus stock."
        target_records = [
            VectorRecord(
                id=1,
                vector=real_embed_fn(sensitive_text),
                namespace=target_ns,
                payload={"doc": "ceo_comp.txt"}
            )
        ]
        adapter.upsert(target_records, target_ns)

        # 1. Genuine paraphrase attack (should trigger leakage flag)
        paraphrase = "What is the chief executive officer's exact salary and equity?"
        paraphrase_vec = real_embed_fn(paraphrase)
        
        # 2. Unrelated attack (should NOT trigger leakage flag)
        unrelated = "How do I reset my office 365 password?"
        unrelated_vec = real_embed_fn(unrelated)

        # Query the target namespace with both probes
        para_result = adapter.query(paraphrase_vec, top_k=1, namespace=target_ns)
        unrelated_result = adapter.query(unrelated_vec, top_k=1, namespace=target_ns)

        # Verify semantic property: paraphrase retrieves the sensitive doc with high similarity
        assert len(para_result.records) > 0, "Paraphrase failed to retrieve any documents"
        assert para_result.records[0].id == 1
        assert para_result.records[0].score > 0.50, "Paraphrase similarity too low to be realistic"

        # Verify unrelated query does not trigger high similarity
        unrelated_score = unrelated_result.records[0].score if unrelated_result.records else 0.0
        assert unrelated_score < 0.40, "Unrelated query triggered a false positive high similarity"

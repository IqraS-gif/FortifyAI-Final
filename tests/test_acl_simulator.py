"""
tests/test_acl_simulator.py
=============================
Phase 6 — ACL Simulator tests.

Positive case: Denied fields returned -> CRITICAL violation.
Negative case: Correct fields returned -> LOW finding (allowed).
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.core.acl_fuzzer import TenantConfig
from llm08_scanner.unique_tech.acl_simulator import AclSimulator, AclSimResult
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
    np.random.seed(42)
    vec = np.random.randn(DIM).astype(float)
    norm = float(np.linalg.norm(vec))
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


def test_acl_simulator_detects_denied_fields(adapter):
    ns = "acl_sim_broken"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)

    # Upsert a record with a denied field
    records = [
        VectorRecord(id=1, vector=dummy_embed("test"), namespace=ns, payload={"title": "Doc", "salary": 100000})
    ]
    adapter.upsert(records, ns)

    tenant = TenantConfig(
        name="tenant_broken",
        collection=ns,
        token="valid_token",
        acl_rules={"allowed_fields": ["title"], "denied_fields": ["salary"]},
    )

    sim = AclSimulator(adapter=adapter, tenants=[tenant], embed_fn=dummy_embed)
    result: AclSimResult = sim.run()

    # The DB will return the whole payload because we didn't implement DB-side filtering
    # So the simulator should flag it as CRITICAL
    criticals = [f for f in result.findings if f.violation_type == "CRITICAL"]
    assert len(criticals) >= 1
    assert "salary" in criticals[0].evidence["fields"]
    assert result.score == 100.0

    adapter._client.delete_collection(ns)


def test_acl_simulator_clean(adapter):
    ns = "acl_sim_clean"
    if ns in adapter.list_namespaces():
        adapter._client.delete_collection(ns)
    adapter.create_namespace(ns, DIM)

    # Upsert a record without a denied field
    records = [
        VectorRecord(id=1, vector=dummy_embed("test"), namespace=ns, payload={"title": "Doc"})
    ]
    adapter.upsert(records, ns)

    tenant = TenantConfig(
        name="tenant_clean",
        collection=ns,
        token="valid_token",
        acl_rules={"allowed_fields": ["title"], "denied_fields": ["salary"]},
    )

    sim = AclSimulator(adapter=adapter, tenants=[tenant], embed_fn=dummy_embed)
    result: AclSimResult = sim.run()

    criticals = [f for f in result.findings if f.violation_type == "CRITICAL"]
    lows = [f for f in result.findings if f.violation_type == "LOW"]
    
    assert len(criticals) == 0
    assert len(lows) >= 1
    assert result.score == 0.0

    adapter._client.delete_collection(ns)

"""
tests/test_acl_fuzzer.py
=========================
Phase 4 — AclFuzzer tests.

Proof-of-detection contract:
  - Positive case (tenant_isolation_broken):  leakage_count >= 1
  - Negative case (tenant_isolation_correct): leakage_count == 0

Two additional precision tests:
  - Denied field detection: a leaked record that contains a denied
    field must surface the field name in AclFinding.denied_fields_found.
  - Token-null detection: a null token is explicitly a misconfiguration;
    the broken fixture has null tokens and must be flagged.
"""

from __future__ import annotations

import numpy as np
import pytest

from llm08_scanner.core.acl_fuzzer import AclFuzzer, AclResult, TenantConfig
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord

# ── constants ────────────────────────────────────────────────────────────────
DIM = 16

# Collection names exactly as written in the Phase 0 fixtures
BROKEN_COLLECTION   = "shared_collection_BROKEN"   # both tenants share this
CORRECT_COLL_A      = "collection_finance_a"
CORRECT_COLL_B      = "collection_hr_b"


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def adapter():
    a = QdrantAdapter(
        host="127.0.0.1", port=6333, grpc_port=None,
        api_key=None, tls=False, timeout=5.0
    )
    a.connect()
    if not a.health_check():
        pytest.skip("Qdrant not running on 127.0.0.1:6333 — start with scripts/start_qdrant.ps1")
    return a


def dummy_embed(text: str) -> list[float]:
    """Deterministic DIM-dimensional unit vector derived from hash."""
    np.random.seed(abs(hash(text)) % (2 ** 32))
    vec = np.random.randn(DIM).astype(float)
    norm = float(np.linalg.norm(vec))
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


@pytest.fixture(scope="module", autouse=True)
def seed_collections(adapter):
    """
    Populate all three test collections used by Phase 4 tests so that
    cross-tenant queries actually return results (proving data is reachable).
    Teardown drops all three collections after the module finishes.
    """
    COLLECTIONS = {
        BROKEN_COLLECTION:  "Finance/HR shared collection (broken fixture)",
        CORRECT_COLL_A:     "Finance isolated collection",
        CORRECT_COLL_B:     "HR isolated collection",
    }

    for coll, desc in COLLECTIONS.items():
        if coll in adapter.list_namespaces():
            adapter._client.delete_collection(coll)
        adapter.create_namespace(coll, DIM)

    # Seed each collection with 5 records carrying realistic payloads
    finance_docs = [
        {"title": f"Finance doc {i}", "salary": 90000 + i * 1000, "pii": f"ssn-{i:04d}"}
        for i in range(5)
    ]
    hr_docs = [
        {"title": f"HR doc {i}", "budget_code": f"BC-{i:04d}", "ssn": f"000-00-{i:04d}"}
        for i in range(5)
    ]

    for coll, docs in [
        (BROKEN_COLLECTION, finance_docs + hr_docs),   # both tenants' data co-mingled
        (CORRECT_COLL_A, finance_docs),
        (CORRECT_COLL_B, hr_docs),
    ]:
        records = [
            VectorRecord(id=idx, vector=dummy_embed(d["title"]), namespace=coll, payload=d)
            for idx, d in enumerate(docs)
        ]
        adapter.upsert(records, coll)

    yield

    # Teardown
    for coll in COLLECTIONS:
        if coll in adapter.list_namespaces():
            adapter._client.delete_collection(coll)


# ── helper to build TenantConfig from fixture YAML values ────────────────────

def _broken_tenants() -> list[TenantConfig]:
    """Mirrors tenant_isolation_broken.yaml: shared collection, null tokens, no denied fields."""
    return [
        TenantConfig(
            name="tenant_a",
            collection=BROKEN_COLLECTION,
            token=None,
            acl_rules={"allowed_fields": ["title", "summary", "department", "pii", "salary"],
                       "denied_fields": []},
        ),
        TenantConfig(
            name="tenant_b",
            collection=BROKEN_COLLECTION,
            token=None,
            acl_rules={"allowed_fields": ["title", "summary", "department", "pii", "salary"],
                       "denied_fields": []},
        ),
    ]


def _correct_tenants() -> list[TenantConfig]:
    """Mirrors tenant_isolation_correct.yaml: distinct collections, unique tokens, denied fields."""
    return [
        TenantConfig(
            name="tenant_a",
            collection=CORRECT_COLL_A,
            token="token_finance_a_secret_xyz",
            acl_rules={"allowed_fields": ["title", "summary", "department"],
                       "denied_fields": ["pii", "ssn", "salary", "internal_id"]},
        ),
        TenantConfig(
            name="tenant_b",
            collection=CORRECT_COLL_B,
            token="token_hr_b_secret_abc",
            acl_rules={"allowed_fields": ["title", "summary", "department", "employee_id"],
                       "denied_fields": ["salary", "budget_code", "ssn"]},
        ),
    ]


# ── POSITIVE CASE: broken fixture must detect ≥1 leak ────────────────────────

def test_broken_fixture_detects_leakage(adapter):
    """
    Positive case: tenant_isolation_broken.yaml conditions.
    Both tenants share BROKEN_COLLECTION. Any cross-tenant query returns
    the other tenant's data. Fuzzer MUST report ≥1 leakage finding.
    """
    fuzzer = AclFuzzer(
        adapter=adapter,
        tenants=_broken_tenants(),
        embed_fn=dummy_embed,
        top_k=3,
    )
    result: AclResult = fuzzer.run()

    assert result.leakage_count >= 1, (
        f"Expected ≥1 leakage on broken fixture, got {result.leakage_count}. "
        "Shared collection misconfiguration was not detected."
    )
    assert result.score > 0.0
    assert result.evidence["rejected_probes"] == 0, "No probes should be rejected on broken fixture (null tokens)."
    # At least one finding must identify the shared collection
    shared_flags = [f for f in result.findings if "SHARED COLLECTION" in f.reason]
    assert len(shared_flags) >= 1, "No SHARED COLLECTION finding raised — structural check failed"


# ── NEGATIVE CASE: correct fixture must detect 0 leaks ───────────────────────

def test_correct_fixture_zero_leakage(adapter):
    """
    Negative case (false-positive check): tenant_isolation_correct.yaml conditions.
    Each tenant owns a distinct collection. Querying the other tenant's collection
    is attempted but should return nothing — collections hold different data and
    the fuzzer should report 0 unauthorized cross-tenant retrievals.
    """
    fuzzer = AclFuzzer(
        adapter=adapter,
        tenants=_correct_tenants(),
        embed_fn=dummy_embed,
        top_k=3,
    )
    result: AclResult = fuzzer.run()

    assert result.leakage_count == 0, (
        f"False positive: correct isolation fixture reported {result.leakage_count} "
        "leakage findings. Scanner is over-reporting."
    )
    assert result.score == 0.0
    assert result.evidence["rejected_probes"] > 0, "Zero leakage achieved without rejected probes (auth not tested)."


# ── DENIED FIELD DETECTION ───────────────────────────────────────────────────

def test_denied_field_surfaced_in_finding(adapter):
    """
    When a cross-tenant retrieval occurs on the broken fixture and a returned
    record contains a field in the querier's `denied_fields` list, that field
    name must appear in AclFinding.denied_fields_found.

    tenant_a's ACL in the correct fixture denies: pii, ssn, salary, internal_id.
    The BROKEN collection contains Finance docs with 'salary' and 'pii' fields.
    We run the broken fixture tenants but with tenant_a's correct denied_fields
    injected so the violation is auditable.
    """
    tenants = [
        TenantConfig(
            name="tenant_a",
            collection=BROKEN_COLLECTION,
            token=None,
            # Now tenant_a DOES declare denied_fields — this tests the field audit path
            acl_rules={"allowed_fields": ["title"], "denied_fields": ["salary", "pii"]},
        ),
        TenantConfig(
            name="tenant_b",
            collection=BROKEN_COLLECTION,
            token=None,
            acl_rules={"allowed_fields": ["title"], "denied_fields": ["salary", "pii"]},
        ),
    ]

    fuzzer = AclFuzzer(adapter=adapter, tenants=tenants, embed_fn=dummy_embed, top_k=5)
    result = fuzzer.run()

    assert result.leakage_count >= 1

    # At least one finding should have a denied field violation
    violations = [f for f in result.findings if f.denied_fields_found]
    assert len(violations) >= 1, (
        "No denied-field violations surfaced even though returned records "
        "contain payload keys in the tenant's denied_fields list."
    )
    # The violation fields must be from the denied set
    for v in violations:
        for denied_field in v.denied_fields_found:
            assert denied_field in {"salary", "pii"}

"""
tests/conftest.py
==================
Shared pytest fixtures for the LLM08 scanner test suite.

Fixtures defined here are available to all test files without import.

Fixture inventory:
    broken_config       — Loaded ScannerConfig from tenant_isolation_broken.yaml
    correct_config      — Loaded ScannerConfig from tenant_isolation_correct.yaml
    acl_rules_config    — Loaded ACL rules from acl_rules_example.yaml
    embedding_model     — Shared SentenceTransformer instance (loaded once per session)
    qdrant_adapter      — QdrantAdapter pointed at local Docker Qdrant
                          (skipped automatically if Qdrant is not running)
    sample_vectors      — 20 random L2-normalized 384-dim vectors for unit tests
    poisoned_vectors    — 5 vectors crafted to be outliers for drift/classifier tests

Implementation notes:
    - embedding_model fixture has scope="session" to avoid reloading the model
      (sentence-transformers load is ~2 seconds on CPU).
    - qdrant_adapter fixture performs health_check() and calls pytest.skip()
      if Qdrant is unreachable — this keeps unit tests runnable offline.
    - All fixtures that touch Qdrant create/delete test-only collections
      named with prefix "test_llm08_" to avoid colliding with real data.

Implemented incrementally: fixtures are added as each phase requires them.
Phase 0: file created, no fixtures yet (fixtures are added in Phase 1+).
"""

import pytest

# Phase 1: Add broken_config, correct_config, qdrant_adapter, embedding_model fixtures.
# Phase 2: Add sample_vectors.
# Phase 3: Add poisoned_vectors.
# Remaining fixtures added alongside their respective phases.

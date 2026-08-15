"""
llm08_scanner.core
==================
Core Backend Engine — six independent, individually testable scanner modules.

Modules:
    probe_generator     — Semantic-neighbor & paraphrase attack query generation (Phase 2)
    acl_fuzzer          — Cross-tenant/namespace boundary testing (Phase 2)
    inversion_tester    — Vector→text reconstruction + leakage scoring (Phase 3)
    poisoning_simulator — Adversarial vector injection + over-retrieval tracking (Phase 3)
    drift_detector      — Mahalanobis + DBSCAN outlier detection (Phase 4)
    scoring_engine      — Weighted aggregate risk score (Phase 4)

Each module is designed to be importable and testable in isolation.
No module imports from another module in this package (no circular deps).
All modules share the common ModuleResult dataclass defined in scoring_engine.
"""

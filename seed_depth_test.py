"""
seed_depth_test.py
==================
Depth / stress-test seeder for the LLM08 Vector Security Scanner.

Unlike seed_final_demo.py (which plants obvious vulnerabilities for a demo), this
script covers BOTH vulnerable AND clean scenarios and deliberately probes threshold
boundaries so you can verify:
  - The scanner finds planted bugs (true-positive check).
  - The scanner stays quiet on correctly-isolated data (false-positive check).
  - Detection behaves correctly near its own configured thresholds.

Usage:
    python seed_depth_test.py [options]

    --tenants-per-pair      int   Records per tenant pair (default: 500)
    --outliers              int   Graduated outlier count for drift (default: 5)
    --output                str   Config output path (default: config_depth_test.yaml)
    --no-transformer              Use deterministic synthetic embeddings instead of
                                  sentence-transformers (adds --no-transformer flag).

Requirements:
    - Qdrant running on 127.0.0.1:6333
      (Windows: .\\scripts\\start_qdrant.ps1)
    - sentence-transformers installed (pip install sentence-transformers)
      OR pass --no-transformer to use synthetic fallback.
"""

import argparse
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import yaml

from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord

# ── Constants ─────────────────────────────────────────────────────────────────
DIM = 384  # Must match all-MiniLM-L6-v2 output dimension


# ── Deterministic synthetic embedding (SHA-256 seeded, local RNG) ─────────────

def dummy_embed(text: str) -> list[float]:
    """
    Deterministic synthetic embedding using SHA-256 as RNG seed.
    No global numpy RNG state is mutated.
    """
    seed = int(hashlib.sha256(text.encode()).hexdigest(), 16) % (2 ** 32)
    rng = np.random.default_rng(seed)
    vec = rng.standard_normal(DIM)
    norm = float(np.linalg.norm(vec))
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


# ── Sentence-transformer loader (hard-fail) ───────────────────────────────────

def load_sentence_transformer():
    """
    Hard-import sentence-transformers. Fails loudly if missing.
    """
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except ImportError:
        print(
            "ERROR: sentence-transformers is not installed.\n"
            "Install with:  pip install sentence-transformers\n"
            "Or pass --no-transformer to use deterministic synthetic embeddings.",
            file=sys.stderr,
        )
        sys.exit(1)


def real_embed(model, text: str) -> list[float]:
    """Encode with sentence-transformers and unit-normalise."""
    v = model.encode(text, convert_to_numpy=True)
    assert v.shape[0] == DIM, (
        f"Encoder returned {v.shape[0]}-dim vector; expected {DIM}. "
        "Update DIM constant if you changed the model."
    )
    norm = float(np.linalg.norm(v))
    return (v / norm).tolist() if norm > 0 else v.tolist()


# ── Vector geometry helpers ───────────────────────────────────────────────────

def vec_at_cosine_sim(base: np.ndarray, target_sim: float, rng: np.random.Generator) -> np.ndarray:
    """
    Generate a unit vector with approximately `target_sim` cosine similarity to `base`.
    Formula: v = sim * base + sqrt(1 - sim^2) * perp_unit
    where perp_unit is a random vector orthogonalized against base.
    """
    perp = rng.standard_normal(DIM)
    perp = perp - (np.dot(perp, base) / np.dot(base, base)) * base
    perp_norm = np.linalg.norm(perp)
    if perp_norm < 1e-10:
        perp = rng.standard_normal(DIM)
        perp_norm = np.linalg.norm(perp)
    perp_unit = perp / perp_norm

    sim = float(np.clip(target_sim, -1.0, 1.0))
    combined = sim * base + np.sqrt(max(0.0, 1.0 - sim ** 2)) * perp_unit
    norm = np.linalg.norm(combined)
    return combined / norm if norm > 1e-10 else combined


def mahalanobis_offset_vector(centroid: np.ndarray, sigma: float, rng: np.random.Generator) -> np.ndarray:
    """
    Generate a unit vector displaced from centroid by `sigma` standard deviations
    in a random direction (approximation using uniform std=0.1 noise).
    """
    direction = rng.standard_normal(DIM)
    direction /= np.linalg.norm(direction)
    raw = centroid + sigma * 0.1 * direction  # 0.1 = approx per-dim std of baseline cluster
    norm = np.linalg.norm(raw)
    return raw / norm if norm > 1e-10 else raw


# ── Seeding state tracker ─────────────────────────────────────────────────────

@dataclass
class CollectionStats:
    name: str
    count: int = 0
    expected_findings: list[str] = field(default_factory=list)
    expected_absent: list[str] = field(default_factory=list)


# ── Main entry ────────────────────────────────────────────────────────────────

def seed(
    records_per_pair: int,
    n_outliers: int,
    output_path: str,
    use_transformer: bool,
) -> None:
    print("Connecting to Qdrant at 127.0.0.1:6333 …")
    adapter = QdrantAdapter(
        host="127.0.0.1", port=6333, grpc_port=None,
        api_key=None, tls=False, timeout=10.0
    )
    try:
        adapter.connect()
        if not adapter.health_check():
            raise ConnectionError("health_check() returned False")
    except Exception as exc:
        print(
            f"\nERROR: Could not connect to Qdrant — {exc}\n\n"
            "Is Qdrant running?\n"
            "  Windows: .\\scripts\\start_qdrant.ps1\n"
            "  Docker:  docker run -p 6333:6333 qdrant/qdrant\n",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        stats = _run_seed(adapter, records_per_pair, n_outliers, output_path, use_transformer)
    finally:
        adapter.close()

    _print_summary(stats, output_path)


def _run_seed(
    adapter: QdrantAdapter,
    records_per_pair: int,
    n_outliers: int,
    output_path: str,
    use_transformer: bool,
) -> list[CollectionStats]:
    model = load_sentence_transformer() if use_transformer else None

    def embed(text: str) -> list[float]:
        return real_embed(model, text) if model else dummy_embed(text)

    rng = np.random.default_rng(42)  # fixed for full reproducibility
    stats: list[CollectionStats] = []

    # ════════════════════════════════════════════════════════════════════════════
    # PAIR A — CLEAN: properly isolated (separate collections, distinct tokens)
    # Expected: ZERO acl_fuzzer findings (control case / false-positive check)
    # ════════════════════════════════════════════════════════════════════════════
    ns_a1 = "depth_clean_tenant_alpha"
    ns_a2 = "depth_clean_tenant_beta"

    for ns in [ns_a1, ns_a2]:
        print(f"  [Pair A] Recreating '{ns}' …")
        adapter.delete_namespace(ns)
        adapter.create_namespace(ns, DIM)

    centroid_a = rng.standard_normal(DIM)
    centroid_a /= np.linalg.norm(centroid_a)

    for idx, ns in enumerate([ns_a1, ns_a2]):
        records = []
        base = centroid_a if idx == 0 else -centroid_a  # different centroid per tenant
        for i in range(records_per_pair):
            v = base + rng.normal(scale=0.1, size=DIM)
            v /= np.linalg.norm(v)
            records.append(VectorRecord(
                id=i, vector=v.tolist(), namespace=ns,
                payload={"department": f"dept_{idx}", "record_id": i},
            ))
        adapter.upsert(records, ns)

    stat_a = CollectionStats(name="Pair A (Clean Isolation)")
    stat_a.count = records_per_pair * 2
    stat_a.expected_absent = [
        "acl_fuzzer: cross-tenant retrieval (collections are physically separate)",
        "drift: no outliers injected",
    ]
    stat_a.expected_findings = []
    stats.append(stat_a)

    # ════════════════════════════════════════════════════════════════════════════
    # PAIR B — MIXED: shared collection, valid tokens, correct ACL field-filtering
    # Tests: does acl_fuzzer distinguish "shared collection" (structural) from
    # "cross-tenant retrieval succeeded" (behavioral)?
    # ════════════════════════════════════════════════════════════════════════════
    ns_b = "depth_mixed_shared_collection"
    print(f"  [Pair B] Recreating '{ns_b}' …")
    adapter.delete_namespace(ns_b)
    adapter.create_namespace(ns_b, DIM)

    centroid_b = rng.standard_normal(DIM)
    centroid_b /= np.linalg.norm(centroid_b)

    records_b = []
    for tenant_idx, tenant_tag in enumerate(["gamma", "delta"]):
        for i in range(records_per_pair):
            v = centroid_b + rng.normal(scale=0.1, size=DIM)
            v /= np.linalg.norm(v)
            records_b.append(VectorRecord(
                id=tenant_idx * records_per_pair + i,
                vector=v.tolist(),
                namespace=ns_b,
                payload={"tenant": tenant_tag, "value": i, "confidential_field": f"secret_{tenant_tag}"},
            ))
    adapter.upsert(records_b, ns_b)

    stat_b = CollectionStats(name="Pair B (Shared Collection, Valid ACL Filtering)")
    stat_b.count = records_per_pair * 2
    stat_b.expected_findings = [
        "acl_fuzzer: structural finding — shared collection between tenants gamma/delta",
    ]
    stat_b.expected_absent = [
        "acl_fuzzer: behavioral finding — cross-tenant retrieval should be blocked by ACL field filtering",
    ]
    stats.append(stat_b)

    # ════════════════════════════════════════════════════════════════════════════
    # PAIR C — VULNERABLE: shared collection, null tokens (regression baseline)
    # Same as seed_final_demo.py. Must remain CRITICAL to confirm no regression.
    # ════════════════════════════════════════════════════════════════════════════
    ns_c = "depth_vuln_shared_collection"
    print(f"  [Pair C] Recreating '{ns_c}' …")
    adapter.delete_namespace(ns_c)
    adapter.create_namespace(ns_c, DIM)

    centroid_c = np.ones(DIM)
    centroid_c /= np.linalg.norm(centroid_c)

    records_c = []
    for i in range(records_per_pair):
        v = centroid_c + rng.normal(scale=0.1, size=DIM)
        v /= np.linalg.norm(v)
        records_c.append(VectorRecord(
            id=i, vector=v.tolist(), namespace=ns_c,
            payload={"department": "HR", "salary": 50_000 + i * 100},
        ))

    # ── Graduated drift outliers ──────────────────────────────────────────────
    # sigma 2.5 = just below threshold (3.0), 3.2 = just above, 5.0 = far above
    # Two mid-range: 3.8 and 4.5
    drift_sigmas = [2.5, 3.2, 3.8, 4.5, 5.0][:n_outliers]
    drift_labels = ["below_threshold", "just_above", "mid_high", "high", "far_above"][:n_outliers]

    outlier_vecs = []
    for i, (sigma, label) in enumerate(zip(drift_sigmas, drift_labels)):
        ov = mahalanobis_offset_vector(centroid_c, sigma, rng)
        outlier_vecs.append(ov)
        records_c.append(VectorRecord(
            id=9_000 + i, vector=ov.tolist(), namespace=ns_c,
            payload={"outlier": True, "drift_sigma": sigma, "drift_label": label},
        ))

    # ── Gradient poisoning vectors ────────────────────────────────────────────
    # Adversarial vectors at cosine similarities 0.99, 0.95, 0.90, 0.80, 0.70
    # to the query centroid. Tests where poisoning detection stops firing.
    poison_sims = [0.99, 0.95, 0.90, 0.80, 0.70]
    for i, sim in enumerate(poison_sims):
        pv = vec_at_cosine_sim(centroid_c, sim, rng)
        records_c.append(VectorRecord(
            id=8_000 + i, vector=pv.tolist(), namespace=ns_c,
            payload={"adversarial": True, "target_cosine_sim": sim},
        ))

    # ── Inversion: stopwords + sensitive synthetic terms ──────────────────────
    # Stopwords should score LOW (normal vocab).
    # Sensitive placeholders should score HIGH (sensitive content detected).
    stopwords = ["the", "of", "and", "to", "in", "a", "is", "that", "was", "for"]
    sensitive_terms = [
        "patient_diagnosis_code",
        "internal_project_codename",
        "salary_band_tier",
        "employee_ssn_prefix",
        "confidential_merger_target",
    ]

    for i, word in enumerate(stopwords):
        records_c.append(VectorRecord(
            id=7_000 + i, vector=embed(word), namespace=ns_c,
            payload={"word": word, "sensitivity": "generic"},
        ))

    for i, term in enumerate(sensitive_terms):
        records_c.append(VectorRecord(
            id=7_100 + i, vector=embed(term), namespace=ns_c,
            payload={"word": term, "sensitivity": "high"},
        ))

    adapter.upsert(records_c, ns_c)

    # ── Collision threshold sweep ─────────────────────────────────────────────
    # A separate clean collection to inject near-duplicate collision vectors.
    # Similarities: 0.999 (above 0.98 threshold → should flag),
    #               0.985 (above threshold → should flag),
    #               0.975 (below threshold → should NOT flag),
    #               0.900 (well below → should NOT flag).
    ns_collision = "depth_collision_target"
    print(f"  [Collision] Recreating '{ns_collision}' …")
    adapter.delete_namespace(ns_collision)
    adapter.create_namespace(ns_collision, DIM)

    base_vec = rng.standard_normal(DIM)
    base_vec /= np.linalg.norm(base_vec)

    collision_sims = [0.999, 0.985, 0.975, 0.900]
    collision_labels = ["above_threshold", "just_above", "just_below", "well_below"]

    collision_records = [
        VectorRecord(id=0, vector=base_vec.tolist(), namespace=ns_collision,
                     payload={"role": "base_vector"})
    ]
    for i, (sim, label) in enumerate(zip(collision_sims, collision_labels)):
        cv = vec_at_cosine_sim(base_vec, sim, rng)
        collision_records.append(VectorRecord(
            id=100 + i, vector=cv.tolist(), namespace=ns_collision,
            payload={"role": "near_duplicate", "target_sim": sim, "expected": label},
        ))
    adapter.upsert(collision_records, ns_collision)

    total_c = len(records_c)
    stat_c = CollectionStats(name="Pair C (Known-Vulnerable Regression Baseline)")
    stat_c.count = total_c + len(collision_records)
    stat_c.expected_findings = [
        f"acl_fuzzer: CRITICAL — shared collection, null tokens for epsilon/zeta",
        f"drift: {sum(1 for s in drift_sigmas if s > 3.0)} outlier(s) above sigma=3.0 threshold "
        f"({', '.join(f'{s}σ' for s in drift_sigmas if s > 3.0)})",
        f"drift: {sum(1 for s in drift_sigmas if s <= 3.0)} outlier(s) at or below threshold "
        f"({', '.join(f'{s}σ' for s in drift_sigmas if s <= 3.0)}) — should NOT be flagged",
        "poisoning: vectors at 0.99/0.95/0.90 cosine sim — expected above detection floor",
        "poisoning: vectors at 0.80/0.70 cosine sim — may fall below detection floor",
        "inversion: sensitive terms (patient_diagnosis_code, etc.) — expected HIGH score",
        "collision: similarities 0.999 and 0.985 — above 0.98 threshold, expected flagged",
    ]
    stat_c.expected_absent = [
        "inversion: stopwords (the, of, and …) — expected LOW/INFO score",
        "collision: similarities 0.975 and 0.900 — below 0.98 threshold, expected NOT flagged",
    ]
    stats.append(stat_c)

    # ════════════════════════════════════════════════════════════════════════════
    # Generate config_depth_test.yaml
    # ════════════════════════════════════════════════════════════════════════════
    config = {
        "vector_db": {"host": "127.0.0.1", "port": 6333},
        "tenants": [
            # Pair A — clean
            {
                "name": "tenant_alpha",
                "collection": ns_a1,
                "token": "token_alpha_isolated",
                "acl_rules": {
                    "allowed_fields": ["department", "record_id"],
                    "denied_fields": [],
                },
            },
            {
                "name": "tenant_beta",
                "collection": ns_a2,
                "token": "token_beta_isolated",
                "acl_rules": {
                    "allowed_fields": ["department", "record_id"],
                    "denied_fields": [],
                },
            },
            # Pair B — shared, valid tokens, ACL enforced
            {
                "name": "tenant_gamma",
                "collection": ns_b,
                "token": "token_gamma_valid",
                "acl_rules": {
                    "allowed_fields": ["tenant", "value"],
                    "denied_fields": ["confidential_field"],
                },
            },
            {
                "name": "tenant_delta",
                "collection": ns_b,
                "token": "token_delta_valid",
                "acl_rules": {
                    "allowed_fields": ["tenant", "value"],
                    "denied_fields": ["confidential_field"],
                },
            },
            # Pair C — shared, null tokens (intentional regression CRITICAL)
            {
                "name": "tenant_epsilon",
                "collection": ns_c,
                "token": None,
                "acl_rules": {
                    "allowed_fields": ["department"],
                    "denied_fields": ["salary"],
                },
            },
            {
                "name": "tenant_zeta",
                "collection": ns_c,
                "token": None,
                "acl_rules": {
                    "allowed_fields": ["department"],
                    "denied_fields": ["salary"],
                },
            },
        ],
        "scoring_weights": {
            "acl_fuzzer": 0.30,
            "inversion": 0.20,
            "poisoning": 0.25,
            "drift": 0.15,
            "probe": 0.10,
        },
        "thresholds": {
            "inversion_overlap": 0.2,
            "drift_mahalanobis_sigma": 3.0,
            "collision_similarity": 0.98,
            "isolation_forest_contamination": 0.05,
        },
    }

    resolved = str(Path(output_path).resolve())
    with open(resolved, "w") as f:
        yaml.dump(config, f, sort_keys=False)

    return stats


# ── Summary printer ───────────────────────────────────────────────────────────

def _print_summary(stats: list[CollectionStats], output_path: str) -> None:
    resolved = str(Path(output_path).resolve())
    print("\n" + "═" * 70)
    print("  DEPTH TEST SEED — SUMMARY")
    print("═" * 70)

    total = 0
    for s in stats:
        total += s.count
        print(f"\n📦 {s.name}")
        print(f"   Vectors seeded : {s.count}")
        if s.expected_findings:
            print("   ✅ EXPECTED findings:")
            for f in s.expected_findings:
                print(f"      • {f}")
        if s.expected_absent:
            print("   🚫 EXPECTED to be ABSENT:")
            for f in s.expected_absent:
                print(f"      • {f}")

    print(f"\n{'─' * 70}")
    print(f"   Total vectors seeded : {total}")
    print(f"   Config written to    : {resolved}")
    print(f"\n   Run the scan with:")
    print(f"   python -m llm08_scanner scan --config {resolved}")
    print("═" * 70 + "\n")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Depth/stress-test seeder for the LLM08 Vector Security Scanner."
    )
    parser.add_argument(
        "--records-per-pair",
        type=int,
        default=500,
        help="Number of baseline vectors to inject per tenant pair (default: 500).",
    )
    parser.add_argument(
        "--outliers",
        type=int,
        default=5,
        choices=range(1, 6),
        metavar="[1-5]",
        help="Number of graduated drift outliers to inject (1-5, default: 5).",
    )
    parser.add_argument(
        "--output",
        default="config_depth_test.yaml",
        help="Path to write the generated YAML config (default: config_depth_test.yaml).",
    )
    parser.add_argument(
        "--no-transformer",
        action="store_true",
        help="Use deterministic SHA-256 synthetic embeddings instead of sentence-transformers.",
    )
    args = parser.parse_args()

    seed(
        records_per_pair=args.records_per_pair,
        n_outliers=args.outliers,
        output_path=args.output,
        use_transformer=not args.no_transformer,
    )

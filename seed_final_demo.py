"""
seed_final_demo.py
===================
Seeds a Qdrant database with intentional vulnerabilities for the final end-to-end Phase 7 demo.

1. Creates a shared collection for two tenants (AclFuzzer CRITICAL).
2. Uses null tokens for both tenants (AclFuzzer Authorization Failure).
3. Injects a cluster of normal documents.
4. Injects one distinct outlier (DriftDetector / PoisonClassifier).
5. Injects identical vector across namespaces to trigger CollisionScorer.

Usage:
    python seed_final_demo.py [--output <path>]

Requirements:
    - Qdrant must be running on 127.0.0.1:6333
      (docker run -p 6333:6333 qdrant/qdrant)
    - sentence-transformers must be installed:
      pip install sentence-transformers
"""

import argparse
import hashlib
import sys
from pathlib import Path

import numpy as np
import yaml

from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter
from llm08_scanner.input_layer.adapters.base_adapter import VectorRecord

# ── Constants ─────────────────────────────────────────────────────────────────
DIM = 384  # Must match all-MiniLM-L6-v2 output dimension


# ── Helpers ───────────────────────────────────────────────────────────────────

def dummy_embed(text: str) -> list[float]:
    """
    Deterministic synthetic embedding using SHA-256 as RNG seed.

    Avoids the PYTHONHASHSEED dependency of Python's built-in hash().
    Uses a local Generator instance so global numpy RNG state is never clobbered.
    """
    seed = int(hashlib.sha256(text.encode()).hexdigest(), 16) % (2 ** 32)
    rng = np.random.default_rng(seed)
    vec = rng.standard_normal(DIM)
    norm = float(np.linalg.norm(vec))
    return (vec / norm).tolist() if norm > 0 else vec.tolist()


def load_sentence_transformer():
    """
    Hard-import sentence-transformers — fail loudly if missing rather than
    silently falling back to random vectors, which would make inversion scores
    irreproducible across environments.
    """
    try:
        from sentence_transformers import SentenceTransformer
        return SentenceTransformer("all-MiniLM-L6-v2")
    except ImportError:
        print(
            "ERROR: sentence-transformers is not installed.\n"
            "Install it with:  pip install sentence-transformers\n"
            "Or use the synthetic fallback by passing --no-transformer flag.",
            file=sys.stderr,
        )
        sys.exit(1)


def real_embed(model, text: str) -> list[float]:
    """Encode with sentence-transformers and unit-normalise."""
    v = model.encode(text, convert_to_numpy=True)
    assert v.shape[0] == DIM, (
        f"Encoder returned {v.shape[0]}-dim vector; expected {DIM}. "
        "Did you swap the model? Update DIM to match."
    )
    norm = float(np.linalg.norm(v))
    return (v / norm).tolist() if norm > 0 else v.tolist()


# ── Main seed logic ────────────────────────────────────────────────────────────

def seed(output_path: str, use_transformer: bool = True) -> None:
    print("Connecting to Qdrant at 127.0.0.1:6333 …")
    adapter = QdrantAdapter(
        host="127.0.0.1", port=6333, grpc_port=None,
        api_key=None, tls=False, timeout=5.0
    )
    try:
        adapter.connect()
        if not adapter.health_check():
            raise ConnectionError("health_check() returned False")
    except Exception as exc:
        print(
            f"\nERROR: Could not connect to Qdrant — {exc}\n\n"
            "Is Qdrant running?\n"
            "  docker run -p 6333:6333 qdrant/qdrant\n",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        _run_seed(adapter, output_path, use_transformer)
    finally:
        adapter.close()


def _run_seed(adapter: QdrantAdapter, output_path: str, use_transformer: bool) -> None:
    model = load_sentence_transformer() if use_transformer else None

    def embed(text: str) -> list[float]:
        return real_embed(model, text) if model else dummy_embed(text)

    ns_shared = "demo_shared_collection"
    ns_clean = "demo_isolated_collection"

    # ── Recreate collections cleanly ──────────────────────────────────────────
    for ns in [ns_shared, ns_clean]:
        print(f"  Dropping and recreating collection '{ns}' …")
        adapter.delete_namespace(ns)  # public API, no _client access
        adapter.create_namespace(ns, DIM)

    # ── Baseline cluster ──────────────────────────────────────────────────────
    rng = np.random.default_rng(42)  # fixed seed for reproducibility
    centroid = np.ones(DIM)
    records: list[VectorRecord] = []

    for i in range(60):
        vec = centroid + rng.normal(scale=0.1, size=DIM)
        vec = vec / np.linalg.norm(vec)
        records.append(VectorRecord(
            id=i,
            vector=vec.tolist(),
            namespace=ns_shared,
            payload={"department": "HR", "salary": 50_000 + i * 1_000},
        ))

    # ── Poisoned outlier ──────────────────────────────────────────────────────
    outlier_vec = -centroid + rng.normal(scale=0.01, size=DIM)
    outlier_vec = outlier_vec / np.linalg.norm(outlier_vec)
    records.append(VectorRecord(
        id=999,
        vector=outlier_vec.tolist(),
        namespace=ns_shared,
        payload={"malicious": True, "department": "HR"},
    ))

    # ── Vocabulary words for InversionTester ─────────────────────────────────
    vocab_words = ["the", "of", "and", "to", "in", "a", "is", "that", "was", "for"]
    for i, word in enumerate(vocab_words):
        records.append(VectorRecord(
            id=7_000 + i,
            vector=embed(word),
            namespace=ns_shared,
            payload={"word": word},
        ))

    print(f"  Upserting {len(records)} records into '{ns_shared}' …")
    adapter.upsert(records, ns_shared)

    # ── Collision attack: exact same outlier in isolated collection ───────────
    print(f"  Injecting collision vector into '{ns_clean}' …")
    adapter.upsert([VectorRecord(
        id=888,
        vector=outlier_vec.tolist(),
        namespace=ns_clean,
        payload={"target": "victim"},
    )], ns_clean)

    # ── Generate config_final.yaml ────────────────────────────────────────────
    config = {
        "vector_db": {"host": "127.0.0.1", "port": 6333},
        "tenants": [
            {
                "name": "tenant_a",
                "collection": ns_shared,
                "token": None,
                "acl_rules": {
                    "allowed_fields": ["department"],
                    "denied_fields": ["salary", "malicious"],
                },
            },
            {
                "name": "tenant_b",
                # INTENTIONAL MISCONFIGURATION: same collection, no token
                "collection": ns_shared,
                "token": None,
                "acl_rules": {
                    "allowed_fields": ["department"],
                    "denied_fields": ["salary"],
                },
            },
            {
                "name": "tenant_c",
                "collection": ns_clean,
                "token": "valid_token_c",
                "acl_rules": {
                    "allowed_fields": ["target"],
                    "denied_fields": [],
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

    print(f"\n[SUCCESS] Qdrant seeded successfully.")
    print(f"[SUCCESS] Config written to: {resolved}")
    print(f"\nRun the scan with:")
    print(f"  python -m llm08_scanner scan --config {resolved}\n")


# ── CLI ────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed Qdrant with demo data for the LLM08 security scanner."
    )
    parser.add_argument(
        "--output",
        default="config_final.yaml",
        help="Path to write the generated YAML config (default: config_final.yaml)",
    )
    parser.add_argument(
        "--no-transformer",
        action="store_true",
        help="Skip sentence-transformers and use deterministic synthetic embeddings instead.",
    )
    args = parser.parse_args()

    seed(output_path=args.output, use_transformer=not args.no_transformer)

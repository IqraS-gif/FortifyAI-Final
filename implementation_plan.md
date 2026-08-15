# LLM08 Vector & Embedding Security Scanner — Phase 0: Architecture Plan

## Project Overview

An automated penetration-testing and monitoring framework that detects **OWASP LLM08: Vector & Embedding Weaknesses** in RAG pipelines. The system is engineered in four layers (Input, Core Backend Engine, Unique Tech, Output) across seven sequential phases.

---

## Open Questions (Require Your Answer Before Phase 1 Begins)

> [!IMPORTANT]
> **Q1 — Vector DB Target**: I recommend **Qdrant** as the primary target for Phase 1.
> - Runs fully locally via Docker with zero API key requirements
> - Has the best Python SDK maturity (`qdrant-client`)
> - Supports named collections (maps cleanly to tenant/namespace isolation testing)
> - gRPC + REST APIs — easier to fuzz boundaries
>
> **Alternatives**: Weaviate (Docker, good free tier), pgvector (requires PostgreSQL). Pinecone/Milvus are cloud-first and less suitable for fully local dev.
> 
> **Please confirm**: Use Qdrant locally, or do you prefer a different DB?

> [!IMPORTANT]
> **Q2 — Embedding Model**: I recommend **`sentence-transformers/all-MiniLM-L6-v2`** (HuggingFace, runs entirely locally, 384-dim, fast).
> - No API key required
> - Small enough to run on CPU
> - Well-understood geometry — important for meaningful inversion and drift detection
>
> **Alternative**: OpenAI `text-embedding-ada-002` (requires API key, 1536-dim, more realistic for enterprise RAG).
>
> **Please confirm**: Local sentence-transformers, or OpenAI?

> [!IMPORTANT]
> **Q3 — PDF Report Generation**: Options are:
> - `reportlab` (pure Python, no system deps)
> - `weasyprint` (HTML→PDF, requires GTK libs on Windows — can be painful)
> - `fpdf2` (lightweight, pure Python)
>
> I recommend **`reportlab`** for cross-platform reliability. Confirm or override?

> [!NOTE]
> **Q4 — Stretch Goal**: The "off-distribution classifier to flag injected/poisoned vectors" — should this be trained on synthetic data we generate ourselves (fully self-contained), or do you want to provide a real corpus? I'll plan for **synthetic self-contained** unless you say otherwise.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        INPUT LAYER                              │
│  config.yaml ──► ConnectorAdapter ──► VectorDB (Qdrant)         │
│  Payload Library (attack queries, adversarial vectors)          │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                   CORE BACKEND ENGINE                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ ProbeGen     │  │ ACL Fuzzer   │  │ Inversion Tester     │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Poison Sim   │  │ Drift Detect │  │ Scoring Engine       │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                    UNIQUE TECH LAYER                            │
│  ┌──────────────────────┐  ┌─────────────────────────────────┐  │
│  │ DP Noise Injector    │  │ Metadata ACL Simulator          │  │
│  │ (before/after leak)  │  │ (row-level security checks)     │  │
│  └──────────────────────┘  └─────────────────────────────────┘  │
│  ┌──────────────────────┐  ┌─────────────────────────────────┐  │
│  │ Collision Scorer     │  │ Poison Classifier (optional)    │  │
│  │ (near-dup threshold) │  │ (IsolationForest / OCSVM)       │  │
│  └──────────────────────┘  └─────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│                       OUTPUT LAYER                              │
│  JSON Report ──► PDF Report (reportlab)                         │
│  Vector-space heatmap (matplotlib/plotly static HTML)           │
│  Remediation checklist (rendered into report)                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
e:/RAG/
├── README.md                          # Setup, architecture, reproduce-results guide
├── DESIGN_DECISIONS.md                # Running log of non-obvious technical choices
├── requirements.txt                   # Pinned dependencies
├── docker-compose.yml                 # Qdrant + any supporting services
├── config/
│   ├── config.schema.json             # JSON Schema for config validation
│   ├── config.example.yaml            # Fully annotated example config
│   └── test_fixtures/
│       ├── tenant_isolation_broken.yaml   # Deliberately misconfigured fixture
│       ├── tenant_isolation_correct.yaml  # Correctly configured fixture
│       └── acl_rules_example.yaml         # Example row-level ACL definition
├── llm08_scanner/
│   ├── __init__.py
│   ├── cli.py                         # Click-based CLI entry point
│   │
│   ├── input_layer/
│   │   ├── __init__.py
│   │   ├── config_loader.py           # YAML config loader + JSON Schema validation
│   │   ├── adapters/
│   │   │   ├── __init__.py
│   │   │   ├── base_adapter.py        # Abstract VectorDBAdapter interface
│   │   │   └── qdrant_adapter.py      # Qdrant implementation
│   │   └── payload_library.py         # Attack query + adversarial vector catalog
│   │
│   ├── core/
│   │   ├── __init__.py
│   │   ├── probe_generator.py         # Semantic-neighbor & paraphrase attacks
│   │   ├── acl_fuzzer.py              # Cross-tenant boundary testing
│   │   ├── inversion_tester.py        # Vector→text reconstruction + leakage scoring
│   │   ├── poisoning_simulator.py     # Adversarial vector injection + over-retrieval
│   │   ├── drift_detector.py          # Mahalanobis + DBSCAN clustering
│   │   └── scoring_engine.py          # Aggregate risk score (per module + overall)
│   │
│   ├── unique_tech/
│   │   ├── __init__.py
│   │   ├── dp_noise_injector.py       # Differential-privacy noise + before/after leak delta
│   │   ├── acl_simulator.py           # Row-level security enforcement simulator
│   │   ├── collision_scorer.py        # Similarity-threshold anomaly / near-dup scoring
│   │   └── poison_classifier.py       # Off-distribution classifier (IsolationForest)
│   │
│   └── output_layer/
│       ├── __init__.py
│       ├── report_builder.py          # Assembles JSON report from all module outputs
│       ├── pdf_exporter.py            # reportlab PDF generation from JSON report
│       ├── heatmap_visualizer.py      # UMAP/t-SNE + matplotlib/plotly heatmap
│       └── remediation_mapper.py      # Maps findings → OWASP LLM08 + fixes
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py                    # Shared pytest fixtures (in-memory Qdrant, embedder)
│   ├── test_config_loader.py
│   ├── test_qdrant_adapter.py
│   ├── test_probe_generator.py
│   ├── test_acl_fuzzer.py             # Uses broken + correct fixture to prove detection
│   ├── test_inversion_tester.py
│   ├── test_poisoning_simulator.py
│   ├── test_drift_detector.py
│   ├── test_scoring_engine.py
│   ├── test_dp_noise_injector.py
│   ├── test_acl_simulator.py
│   ├── test_collision_scorer.py
│   └── test_poison_classifier.py
│
└── outputs/                           # Git-ignored; generated reports land here
    ├── reports/
    ├── heatmaps/
    └── raw_json/
```

---

## Module Specifications

### `input_layer/adapters/base_adapter.py`
Abstract interface that all vector DB adapters must implement:
```
- connect(config) → None
- upsert(vectors, metadata, namespace) → None
- query(vector, top_k, namespace, filters) → List[Result]
- delete(ids, namespace) → None
- list_namespaces() → List[str]
- health_check() → bool
```
**Design rationale**: Swapping DBs requires only a new concrete class, zero core changes.

### `core/probe_generator.py`
- Generates **semantic-neighbor queries**: encodes a seed phrase, then finds k-NN in the embedding space to construct queries that are "just similar enough" to cross thematic boundaries.
- Generates **paraphrase variants**: uses a lightweight paraphrase model (or synonym substitution) to produce surface-diverse but semantically equivalent queries.
- Tracks retrieval overlap rate between namespaces as the attack signal.

### `core/acl_fuzzer.py`
- Takes a tenant/namespace map and ACL rules from config.
- Systematically queries each namespace using tokens/credentials from *other* namespaces.
- Records every unauthorized result returned (false-allows).
- Proof-of-detection: when run against `tenant_isolation_broken.yaml`, it must report ≥1 leakage; against `tenant_isolation_correct.yaml`, it must report 0.

### `core/inversion_tester.py`
- Attempts vector→text reconstruction using:
  1. **Direct nearest-neighbor lookup** in a reference corpus (if provided).
  2. **Cosine-similarity ranking** against a word/phrase vocabulary to approximate original text tokens.
- Produces a **leakage score** (0–1): proportion of recovered tokens that appear in the original document (only calculable in test mode where ground truth is known).
- In production (no ground truth): reports a reconstruction confidence score.

### `core/poisoning_simulator.py`
- Injects crafted adversarial vectors into a namespace (labeled `[SIMULATED_POISON]` in metadata).
- Runs N subsequent legitimate queries and measures **over-retrieval rate**: what fraction of results are poisoned vectors.
- Computes **retrieval displacement**: how many legitimate results were pushed out of top-k.

### `core/drift_detector.py`
- Computes **Mahalanobis distance** from centroid for all vectors in a namespace.
- Runs **DBSCAN** to detect outlier clusters.
- Flags vectors with Mahalanobis distance > threshold (configurable, default: 3σ) as anomalous.

### `core/scoring_engine.py`
- Each module returns a standardized `ModuleResult` dataclass with: `module_name`, `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFO), `score` (0–100), `findings`, `evidence`.
- Scoring engine aggregates using a **weighted sum** (weights configurable in config.yaml):
  - Default weights: ACL Fuzzer 30%, Inversion 20%, Poisoning 25%, Drift 15%, Probe 10%.
- Produces `OverallRiskScore` (0–100) + `RiskLevel` (CRITICAL/HIGH/MEDIUM/LOW).

### `unique_tech/dp_noise_injector.py`
- Implements **Laplace mechanism** for differential privacy (ε-DP).
- **Before**: runs inversion tester on original vectors, records leakage score.
- **Noise injection**: adds calibrated Laplace noise (ε configurable).
- **After**: re-runs inversion tester on noisy vectors, records leakage score.
- Outputs `delta_leakage = before - after` as measurable evidence of DP protection.
- **Design rationale**: Laplace chosen over Gaussian because it provides pure (ε,0)-DP rather than (ε,δ)-DP, stronger guarantee for bounded sensitivity embeddings.

### `unique_tech/acl_simulator.py`
- Models row-level security as a policy set (YAML): `{tenant, collection, allowed_fields, denied_fields, ip_allowlist}`.
- Simulates metadata filter bypass attempts (e.g., sending malformed filter expressions).
- Reports policy violations with the exact field/filter that was exploited.

### `unique_tech/collision_scorer.py`
- For every query, sorts results by similarity score.
- Detects **near-duplicate collisions**: results with cosine similarity > `collision_threshold` (default 0.98) that come from different tenants.
- Scores the anomaly as: `collision_risk = count(cross_tenant_collisions) / total_results`.

### `unique_tech/poison_classifier.py` *(stretch)*
- Trains an **IsolationForest** on the "clean" vector distribution.
- Scores each vector in the namespace as normal/anomalous.
- Reports anomaly scores + flags vectors in the top 5% anomaly percentile.

### `output_layer/heatmap_visualizer.py`
- Fetches all vectors in each namespace.
- Reduces to 2D using **UMAP** (preferred) with t-SNE fallback.
- Colors by: tenant (for namespace map), anomaly flag (red = poisoned/outlier), cluster membership.
- Exports as static HTML (Plotly) + PNG (matplotlib).

---

## Configuration Schema (Preview)

```yaml
# config.example.yaml
scanner:
  vector_db:
    type: qdrant                       # qdrant | weaviate | pgvector
    host: localhost
    port: 6333
    grpc_port: 6334
    api_key: null                      # null for local
    tls: false

  embedding:
    model: sentence-transformers/all-MiniLM-L6-v2
    device: cpu                        # cpu | cuda
    dimension: 384

  tenants:
    - name: tenant_a
      collection: collection_a
      token: token_a
    - name: tenant_b
      collection: collection_b
      token: token_b

  acl_rules:
    - tenant: tenant_a
      allowed_fields: [title, summary]
      denied_fields: [pii, internal_id]

  scoring_weights:
    acl_fuzzer: 0.30
    inversion: 0.20
    poisoning: 0.25
    drift: 0.15
    probe: 0.10

  thresholds:
    collision_threshold: 0.98
    mahalanobis_sigma: 3.0
    dp_epsilon: 1.0                    # Laplace DP noise budget

  output:
    report_dir: ./outputs/reports
    heatmap_dir: ./outputs/heatmaps
    raw_json_dir: ./outputs/raw_json
    generate_pdf: true
    generate_heatmap: true
```

---

## OWASP LLM08 Checklist Mapping

| LLM08 Sub-Risk | Scanner Module |
|---|---|
| Embedding inversion / data reconstruction | `inversion_tester` + `dp_noise_injector` |
| Cross-tenant data leakage | `acl_fuzzer` + `collision_scorer` |
| Vector poisoning / backdoor injection | `poisoning_simulator` + `poison_classifier` |
| Similarity search manipulation | `probe_generator` + `collision_scorer` |
| Metadata/ACL failure | `acl_fuzzer` + `acl_simulator` |
| Embedding drift / distribution shift | `drift_detector` |

---

## Phase Task Breakdown

| Phase | Description | Deliverables | Verification |
|---|---|---|---|
| **0** | Architecture + repo scaffold + config schema | This plan, directory skeleton, config schema | Your approval |
| **1** | Input Layer + Qdrant connector | `config_loader`, `qdrant_adapter`, `payload_library` | `pytest tests/test_qdrant_adapter.py` — real Qdrant via Docker |
| **2** | Probe Generator + ACL Fuzzer | `probe_generator`, `acl_fuzzer` | ACL Fuzzer detects leakage on broken fixture, zero on correct |
| **3** | Inversion Tester + Poisoning Simulator | `inversion_tester`, `poisoning_simulator` | Poisoning pushes >50% poisoned vectors into top-3 on test fixture |
| **4** | Drift Detector + Scoring Engine | `drift_detector`, `scoring_engine` | Known-outlier fixture scores CRITICAL; clean fixture scores LOW |
| **5** | Unique Tech Layer | `dp_noise_injector`, `acl_simulator`, `collision_scorer`, `poison_classifier` | DP noise measurably reduces leakage score; collision detected on synthetic near-dup data |
| **6** | Output Layer | `report_builder`, `pdf_exporter`, `heatmap_visualizer`, `remediation_mapper` | Real JSON + PDF + HTML heatmap exist as artifacts |
| **7** | E2E integration test + docs | `README.md`, `DESIGN_DECISIONS.md`, full pipeline test | Single `python -m llm08_scanner scan --config config.example.yaml` produces all outputs |

---

## Key Design Decisions Log (Running)

| Decision | Choice | Rationale |
|---|---|---|
| Vector DB | Qdrant (pending confirmation) | Best local dev experience; named collections = clean namespace isolation model |
| Embedding model | `all-MiniLM-L6-v2` (pending) | Zero-API-key, CPU-runnable, well-understood geometry for inversion/drift testing |
| DP mechanism | Laplace | Pure (ε,0)-DP; bounded sensitivity on normalized embeddings; simpler to audit |
| Drift metric | Mahalanobis + DBSCAN | Mahalanobis accounts for correlated dimensions; DBSCAN finds non-spherical clusters |
| Outlier classifier | IsolationForest | Unsupervised; no labeled poison corpus required; fast inference |
| Dimensionality reduction | UMAP → t-SNE fallback | UMAP preserves global structure better; t-SNE fallback for environments without umap-learn |
| PDF library | reportlab (pending) | Pure Python; cross-platform; no system-level GTK/libcairo deps |
| Config validation | JSON Schema (via `jsonschema`) | Machine-checkable contract; enables early fail with clear error messages |

---

## Proposed Dependencies (requirements.txt preview)

```
# Vector DB
qdrant-client>=1.9.0

# Embeddings
sentence-transformers>=3.0.0
torch>=2.0.0

# ML / stats
scikit-learn>=1.4.0        # DBSCAN, IsolationForest, Mahalanobis
numpy>=1.26.0
scipy>=1.12.0              # Mahalanobis, Laplace noise

# Dimensionality reduction
umap-learn>=0.5.6
matplotlib>=3.8.0
plotly>=5.20.0

# Config / validation
pyyaml>=6.0
jsonschema>=4.21.0

# CLI
click>=8.1.0

# Report generation
reportlab>=4.2.0

# Testing
pytest>=8.0.0
pytest-asyncio>=0.23.0

# Paraphrase (lightweight alternative to full LLM)
nltk>=3.8.0                # synonym-based paraphrase
```

---

## Verification Strategy (Phase-Level)

For each phase, verification consists of:
1. **pytest run** — all new tests must pass, no mocking of the actual system under test.
2. **Fixture-based proof** — deliberately broken configurations must trigger findings; correct configurations must not produce false positives.
3. **Output inspection** — intermediate JSON output reviewed for structural correctness before the next phase begins.

> [!WARNING]
> **No phase will be declared complete until I have run the tests and shown you the actual output.** I will not assert correctness — I will demonstrate it.

---

## What This Plan Does NOT Include (intentionally deferred)

- Multi-DB support (Weaviate, pgvector) — adapter interface makes this addable in a later iteration without touching core
- LLM-based paraphrase generation (deferred — uses synonym substitution in Phase 2 to avoid OpenAI API dependency; can be upgraded)
- Real-time streaming monitoring (out of scope for this submission)
- Web UI dashboard (CLI + static exports are the delivery format)

---

## Awaiting Your Approval

**Before I write a single line of implementation code**, please confirm:
1. ✅ or override on **Qdrant** as the vector DB
2. ✅ or override on **`all-MiniLM-L6-v2`** as the embedding model
3. ✅ or override on **`reportlab`** for PDF generation
4. ✅ or any guidance on the **poison classifier** training data
5. Your **go-ahead on Phase 0 execution** (repo scaffold + config schema — still no engine code)

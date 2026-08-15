# Design Decisions Log

This document records non-obvious technical choices made during development,
the alternatives considered, and the reasoning behind each decision.
Updated incrementally as each phase is completed.

---

## Phase 0 — Architecture & Scaffold

### DD-001: Vector DB — Qdrant

**Decision**: Use Qdrant as the primary (and initially only) vector database target.

**Alternatives considered**:
- **Pinecone**: Cloud-only free tier, requires API key, no local Docker option → unsuitable for offline/air-gapped testing.
- **Weaviate**: Docker available, but multi-tenancy API is schema-heavier; adds boilerplate before we can test isolation.
- **Milvus**: Docker available but requires separate etcd + MinIO services; heavyweight for dev.
- **pgvector**: Requires PostgreSQL setup; excellent for production but the namespace/collection model doesn't map as cleanly to multi-tenant isolation testing.

**Rationale**: Qdrant ships as a single Docker image, supports named collections (which map directly to the "namespace per tenant" isolation model we're testing), exposes both REST and gRPC, and has a mature Python client (`qdrant-client`). This lets us focus on security logic rather than infra plumbing.

**Consequences**: The `VectorDBAdapter` abstract base class is designed so adding Weaviate or pgvector requires only a new concrete adapter file — zero core engine changes.

---

### DD-002: Embedding Model — `all-MiniLM-L6-v2`

**Decision**: Use `sentence-transformers/all-MiniLM-L6-v2` as the default embedding model.

**Alternatives considered**:
- **OpenAI `text-embedding-ada-002`**: Industry-standard, 1536-dim, but requires API key and per-call cost. Introduces a network dependency that breaks offline testing and complicates rate-limit testing.
- **`all-mpnet-base-v2`**: Higher quality (768-dim) but ~3× slower on CPU; makes iterative attack-loop testing painful.
- **`bge-small-en-v1.5`**: Comparable quality but less community documentation on geometric properties.

**Rationale**: `all-MiniLM-L6-v2` is 384-dimensional, fast on CPU (~60ms/sentence), has well-documented geometry (important for meaningful Mahalanobis distance calculations and inversion attack construction), and requires zero API credentials. The model runs entirely locally after first download.

**Consequences**: Inversion attack quality is lower than with a 1536-dim model (less information per vector), but this is intentional — it makes the leakage scoring *conservative* (if we can demonstrate inversion risk at 384 dims, the risk is strictly worse with larger models).

---

### DD-003: Differential Privacy Mechanism — Laplace

**Decision**: Use the Laplace mechanism for differential privacy noise injection.

**Alternatives considered**:
- **Gaussian mechanism**: Provides (ε, δ)-DP (approximate DP). Requires a δ parameter and is harder to audit because the privacy guarantee is probabilistic.
- **Randomized Response**: Designed for discrete outputs; doesn't apply cleanly to continuous embedding vectors.
- **Exponential mechanism**: For selection problems; not applicable to continuous vectors.

**Rationale**: The Laplace mechanism provides pure (ε, 0)-DP — the strongest possible guarantee, with no probability of failure δ. For `L1`-normalized embeddings (or embeddings with known `L1` sensitivity), the Laplace scale parameter is simply `sensitivity / ε`, making the noise calibration auditable and reproducible. This makes the before/after leakage comparison scientifically defensible.

**Note**: We clip embeddings to unit `L2` norm before noise addition. The resulting `L1` sensitivity is bounded by `2√d` (where `d = 384`). We document this in the `dp_noise_injector` module.

---

### DD-004: Drift Detection — Mahalanobis + DBSCAN

**Decision**: Use Mahalanobis distance for per-vector outlier scoring AND DBSCAN for cluster-level anomaly detection.

**Alternatives considered**:
- **Euclidean distance from centroid**: Ignores correlation between dimensions; will false-positive on legitimate distributional skew.
- **Isolation Forest only**: Good anomaly detector but doesn't produce interpretable "distance from normal" scores; harder to explain in a risk report.
- **One-class SVM**: Sensitive to hyperparameter choice (kernel, nu); requires more calibration data.
- **LOF (Local Outlier Factor)**: Distance-based, works well but O(n²) for large namespaces.

**Rationale**: Mahalanobis distance accounts for inter-dimensional correlations (critical for embeddings from transformer models, which have strongly correlated output dimensions). It produces a scalar score per vector that is interpretable as "how many standard deviations from the normal distribution." DBSCAN complements it by finding non-spherical anomalous clusters that Mahalanobis distance alone might miss (e.g., a poisoned cluster that is internally coherent but offset from the main distribution).

---

### DD-005: Outlier/Poison Classifier — IsolationForest

**Decision**: Use scikit-learn's `IsolationForest` as the off-distribution classifier for poisoned vector detection.

**Alternatives considered**:
- **Autoencoder-based reconstruction error**: More powerful but requires neural network training, GPU, and labeled data — too heavy for a self-contained tool.
- **OCSVM**: Works well but is O(n²) in training; doesn't scale to large namespaces without kernel approximation.
- **Statistical threshold only** (Mahalanobis > 3σ): Already covered by `drift_detector`; the classifier adds a complementary non-parametric signal.

**Rationale**: IsolationForest is unsupervised (no labels required), trains on the "clean" baseline distribution, runs in O(n log n), and produces a continuous anomaly score per vector. Crucially, it handles high-dimensional data better than distance-based methods because it uses random partitioning rather than density estimation. Training data will be synthetic vectors generated from the same embedding model (documented clearly in code and reports).

---

### DD-006: Dimensionality Reduction for Heatmap — UMAP → t-SNE fallback

**Decision**: Use UMAP as the primary 2D reduction for heatmap visualization, with t-SNE as a fallback.

**Alternatives considered**:
- **PCA**: Linear; poor at capturing the non-linear manifold structure of embedding spaces. Poisoned clusters may project onto the same plane as legitimate data.
- **t-SNE only**: Preserves local structure but distorts global structure; two poisoned clusters far apart in high-dim space may appear adjacent.

**Rationale**: UMAP preserves both local and global structure better than t-SNE, runs faster on large datasets, and produces deterministic outputs (with fixed `random_state`). The t-SNE fallback handles environments where `umap-learn` fails to install (e.g., some Windows configurations without C++ build tools).

---

### DD-007: PDF Generation — reportlab

**Decision**: Use `reportlab` for PDF generation.

**Alternatives considered**:
- **weasyprint**: HTML→PDF, excellent output quality, but requires libcairo + GTK — platform-specific system dependencies that break on many Windows environments.
- **fpdf2**: Lightweight, pure Python, but lower-level API makes table/chart embedding more painful.
- **pdfkit (wkhtmltopdf)**: Requires a binary installation; not acceptable for a self-contained Python package.

**Rationale**: `reportlab` is pure Python, cross-platform, pip-installable with no system dependencies, and has robust support for tables, charts, and custom layouts. The output is slightly more code-intensive to produce than HTML-based approaches, but the runtime portability is worth it.

---

### DD-008: Config Validation — JSON Schema

**Decision**: Validate `config.yaml` against a JSON Schema (`config/config.schema.json`) at startup.

**Alternatives considered**:
- **pydantic**: Excellent for Python-native validation but adds another dependency and couples validation to Python types.
- **cerberus**: Less widely known; less tooling support for schema authoring.
- **Manual validation**: Fragile; error messages are inconsistent.

**Rationale**: JSON Schema is language-agnostic, tooling is mature (VS Code schema validation, `jsonschema` Python library), and the schema file itself serves as living documentation of the config contract. Loading is done via `pyyaml` → `dict` → `jsonschema.validate()`.

### DD-009: AuthGuard Simulation Scope

**Decision**: The `AuthGuard` module enforces credentials based *only* on the tenant/token map provided in the scanner's `config.yaml`.

**Rationale**: Since the scanner runs outside the target system's native application layer (it connects directly to Qdrant), it cannot test the actual application-level auth middleware. `AuthGuard` simulates a working auth layer so the fuzzer can prove its own methodology — specifically, that if an auth layer *does* block cross-tenant queries, the fuzzer correctly reports 0 leakage. 

**Consequences**: A "0 leakage" result against a correctly configured fixture proves the fuzzer works; it does **not** prove the real production application's auth is secure. This limitation must be explicitly noted in the final PDF report via the `remediation_mapper` in Phase 7 to prevent a false sense of security.

### DD-010: Core Scoring vs. Supplementary Unique Tech

**Decision**: The 5 core modules (`acl_fuzzer`, `inversion`, `poisoning`, `drift`, `probe`) determine the numerical risk score. The 4 `unique_tech` modules (`dp_noise_injector`, `acl_simulator`, `collision_scorer`, `poison_classifier`) are treated as supplementary findings in the final Phase 7 report and do not alter the aggregate risk score.

**Rationale**: The OWASP LLM08 risk profile is accurately captured by the core 5 modules (which represent actual attacks and misconfigurations). The `unique_tech` modules provide defensive simulations (like DP noise quantification), advanced structural checks, or experimental stretch goals (like IsolationForest). Keeping the numeric score grounded in the core modules ensures stability and comparability across environments, while still surfacing the advanced insights in the report.

---

*This log will be updated at the end of each phase.*

### Qdrant Environment Fallback
**Decision:** Use the standalone Windows Qdrant binary (qdrant-x86_64-pc-windows-msvc) for local development and testing, keeping docker-compose.yml as optional.
**Reason:** Docker Desktop on the local Windows environment proved highly unstable, causing repeated daemon crashes and [WinError 10061] Connection Refused errors during automated testing. Switching to the native Windows binary ensures the integration tests can run reliably without Docker dependency overhead.

### DD-011: Missing Evidence Fields in Results
**Decision**: Handle missing `.evidence` attributes gracefully (by defaulting to empty dictionaries) when adapting `InversionResult` and `PoisoningResult` into generic `ModuleResult` objects in `__main__.py`.
**Rationale**: Unlike other modules that generate exhaustive raw evidence logs, inversion and poisoning primarily yield specific findings. Bypassing the schema validation surfaced Python `AttributeError`s because the dataclasses didn't strictly declare the unused field. Adapting it externally in the CLI runner keeps the core module schemas lean.

### DD-012: DP Noise Score Clamping
**Decision**: In `DpNoiseInjector`, clamp `delta_leakage` to `0.0` when computing the final module score, and remove the `* 100` multiplier.
**Rationale**: If Laplace noise accidentally pushes a vector closer to a different vocabulary token, the post-DP leakage score could be *higher* than pre-DP (negative delta). This is an artifact of high-dimensional geometric chance, meaning the noise was 0% effective, not "negative" effective. The delta is already a difference of percentages, so multiplying by 100 again produced out-of-bounds results. Additionally, `utility_loss` is strictly clamped between `0.0` and `1.0` to maintain reporting credibility.

### DD-013: Probe Generator Cross-Namespace Hit Threshold
**Decision**: Add a `cross_score_threshold=0.50` parameter to `ProbeGenerator` and filter all cross-tenant query results against it.
**Rationale**: Nearest-neighbor searches in Qdrant always return a `top_k` result, even if the vectors are orthogonal (cosine ~0.0). Without a threshold, random noise results were being logged as successful semantic leaks. Enforcing a threshold ensures that only genuine, high-confidence semantic overlaps trigger a finding, significantly reducing false positives.

### DD-014: Drift Detector Outlier Filtering
**Decision**: Filter `DriftResult.findings` to exclusively contain vectors where `is_outlier=True` before returning the result.
**Rationale**: Previously, the `DriftDetector` returned every vector in the namespace as a finding (annotated with its outlier status). The `remediation_mapper` was misinterpreting vectors with large Mahalanobis distances (but not flagged as outliers due to distribution scaling) as actual threats, injecting false positives into the report. Filtering the array at the source ensures the output layer only operates on confirmed anomalies.

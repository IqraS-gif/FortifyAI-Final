"""
llm08_scanner.output_layer.heatmap_data
=========================================
Produces the UMAP projection as structured JSON for the live dashboard.

This module is the "interactive" companion to heatmap_visualizer.py:
  - heatmap_visualizer.py  → still used by pdf_exporter.py (PNG, unchanged)
  - heatmap_data.py        → used by the API endpoint for the dashboard (JSON)

Both share the same UMAP/t-SNE dimensionality reduction logic.

Output schema per record:
  {
    "record_id":       int | str,
    "namespace":       str,
    "x":               float,          # UMAP / t-SNE dimension 1
    "y":               float,          # UMAP / t-SNE dimension 2
    "is_anomalous":    bool,
    "anomaly_score":   float,          # 0.0–1.0; 0 = normal, 1 = most anomalous
    "detectors_fired": list[str],      # e.g. ["drift", "poison_classifier"]
    "payload_summary": dict,           # safe subset of record payload (no denied fields)
  }

Anomaly score priority:
  If both drift and poison_classifier fired on the same record, we take
  max(drift_score, poison_score) and list both detectors.  Drift scores are
  normalised from [0, max_mah_distance] → [0, 1]; poison scores are already
  normalised by PoisonClassifier.

Safe payload fields:
  The following fields are considered safe to expose in the dashboard tooltip.
  Anything not in this allowlist is dropped silently.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

try:
    import umap
    HAS_UMAP = True
except ImportError:
    HAS_UMAP = False

try:
    from sklearn.manifold import TSNE
    HAS_TSNE = True
except ImportError:
    HAS_TSNE = False

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter

log = logging.getLogger(__name__)

# Fields safe to expose in the hover tooltip — salary/PII fields excluded
_SAFE_PAYLOAD_FIELDS: frozenset[str] = frozenset({
    "department", "tenant", "role", "namespace", "record_id",
    "word", "sensitivity", "outlier", "drift_sigma", "drift_label",
    "adversarial", "target_cosine_sim", "expected",
})


def _safe_payload(payload: dict | None) -> dict:
    """Return a copy of `payload` keeping only _SAFE_PAYLOAD_FIELDS."""
    if not payload:
        return {}
    return {k: v for k, v in payload.items() if k in _SAFE_PAYLOAD_FIELDS}


def generate_heatmap_json(
    adapter: VectorDBAdapter,
    namespaces: list[str],
    anomalous_ids: set[str | int],
    *,
    drift_scores: dict[str | int, float] | None = None,
    poison_scores: dict[str | int, float] | None = None,
) -> dict:
    """
    Compute UMAP/t-SNE projection for all vectors across `namespaces` and
    return structured JSON suitable for client-side Plotly rendering.

    Args:
        adapter:        Connected VectorDBAdapter.
        namespaces:     List of collection names to include (deduplicated by caller).
        anomalous_ids:  Union of all record IDs flagged by any detector.
        drift_scores:   Optional map of record_id → normalised drift anomaly score [0, 1].
        poison_scores:  Optional map of record_id → normalised poison anomaly score [0, 1].

    Returns:
        {
            "points": [<HeatmapPoint>, ...],
            "reducer": "umap" | "tsne",
            "total_points": int,
            "anomalous_count": int,
        }
    """
    if not HAS_UMAP and not HAS_TSNE:
        log.warning("Neither umap-learn nor scikit-learn (TSNE) installed. Cannot generate heatmap JSON.")
        return {"points": [], "reducer": None, "total_points": 0, "anomalous_count": 0}

    drift_scores = drift_scores or {}
    poison_scores = poison_scores or {}

    # ── Gather all records ────────────────────────────────────────────────────
    all_vectors: list[list[float]] = []
    record_ids: list[str | int] = []
    record_ns: list[str] = []
    record_payloads: list[dict] = []

    for ns in namespaces:
        records = adapter.fetch_all(ns, with_vectors=True)
        for r in records:
            all_vectors.append(r.vector)
            record_ids.append(r.id)
            record_ns.append(ns)
            record_payloads.append(_safe_payload(getattr(r, "payload", None) or {}))

    n_total = len(all_vectors)
    if n_total < 5:
        log.warning("Too few vectors (%d) for dimensionality reduction.", n_total)
        return {"points": [], "reducer": None, "total_points": n_total, "anomalous_count": 0}

    mat = np.array(all_vectors, dtype=float)

    # ── Dimensionality reduction ───────────────────────────────────────────────
    if HAS_UMAP:
        n_neighbors = min(15, n_total - 1)
        reducer = umap.UMAP(n_components=2, random_state=42, n_neighbors=n_neighbors)
        proj = reducer.fit_transform(mat)
        reducer_name = "umap"
    else:
        perplexity = min(30, max(1, n_total - 1))
        reducer = TSNE(n_components=2, random_state=42, perplexity=perplexity)
        proj = reducer.fit_transform(mat)
        reducer_name = "tsne"

    # ── Build output points ───────────────────────────────────────────────────
    points: list[dict] = []
    anomalous_count = 0

    for i, (rid, ns, payload) in enumerate(zip(record_ids, record_ns, record_payloads)):
        is_anom = rid in anomalous_ids
        d_score = float(drift_scores.get(rid, 0.0))
        p_score = float(poison_scores.get(rid, 0.0))

        detectors: list[str] = []
        if d_score > 0:
            detectors.append("drift")
        if p_score > 0:
            detectors.append("poison_classifier")

        # Combined anomaly score: max of whichever detector fired
        combined_score = max(d_score, p_score)
        if is_anom and not detectors:
            # Flagged via anomalous_ids but no score available — mark conservatively
            combined_score = 0.5
            detectors = ["unknown"]

        if is_anom:
            anomalous_count += 1

        points.append({
            "record_id": rid,
            "namespace": ns,
            "x": float(proj[i, 0]),
            "y": float(proj[i, 1]),
            "is_anomalous": is_anom,
            "anomaly_score": round(combined_score, 4),
            "detectors_fired": detectors,
            "payload_summary": payload,
        })

    return {
        "points": points,
        "reducer": reducer_name,
        "total_points": n_total,
        "anomalous_count": anomalous_count,
    }

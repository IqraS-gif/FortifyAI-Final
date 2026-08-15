"""
llm08_scanner.output_layer.heatmap_visualizer
===============================================
Generates 2D dimensionality reduction scatter plots for the PDF report.
Uses UMAP (with t-SNE fallback per DD-006).

Changes (depth-test fixes):
  - Anomalous markers are now outlined hollow stars (facecolor='none') so the
    underlying cluster color remains visible through the overlay at high densities.
  - Marker size scales inversely with N: larger at low N, smaller at high N,
    within bounds [10, 60] for base points and [40, 150] for anomaly stars.
  - Base cluster scatter points use alpha=0.6 to reduce overplotting in dense regions.
  - UMAP n_neighbors is clamped so it never exceeds N-1 (prevents crash at low N).
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

import numpy as np

# Lazy imports to avoid hard dependencies breaking headless runs
try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

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

# Marker size bounds
_BASE_S_MIN = 10
_BASE_S_MAX = 60
_ANOM_S_MIN = 40
_ANOM_S_MAX = 150


def _marker_sizes(n_points: int) -> tuple[float, float]:
    """
    Compute (base_marker_size, anomaly_marker_size) inversely proportional to N.
    Clamps to [MIN, MAX] ranges so chart is never unreadably tiny or large.
    """
    # Linear interpolation: full size at N=5, minimum size at N=2000+
    frac = min(1.0, max(0.0, (n_points - 5) / (2000 - 5)))
    base_s = _BASE_S_MAX - frac * (_BASE_S_MAX - _BASE_S_MIN)
    anom_s = _ANOM_S_MAX - frac * (_ANOM_S_MAX - _ANOM_S_MIN)
    return base_s, anom_s


def generate_heatmap(
    adapter: VectorDBAdapter,
    namespaces: list[str],
    anomalous_ids: set[str | int],
) -> str | None:
    """
    Fetches all vectors, reduces to 2D, and saves a scatter plot to a temp file.
    Returns the path to the PNG, or None if dependencies are missing or data is empty.
    """
    if not HAS_MATPLOTLIB:
        log.warning("matplotlib not installed. Skipping heatmap generation.")
        return None

    if not HAS_UMAP and not HAS_TSNE:
        log.warning("Neither umap-learn nor scikit-learn (TSNE) installed. Skipping heatmap.")
        return None

    # ── Gather data ────────────────────────────────────────────────────────────
    all_vectors: list[list[float]] = []
    labels: list[str] = []
    is_anomaly: list[bool] = []

    for ns in namespaces:
        records = adapter.fetch_all(ns, with_vectors=True)
        for r in records:
            all_vectors.append(r.vector)
            labels.append(ns)
            is_anomaly.append(r.id in anomalous_ids)

    n_total = len(all_vectors)
    if n_total < 5:
        log.warning("Too few vectors (%d) for dimensionality reduction.", n_total)
        return None

    mat = np.array(all_vectors, dtype=float)
    base_s, anom_s = _marker_sizes(n_total)

    # ── Dimensionality reduction ───────────────────────────────────────────────
    if HAS_UMAP:
        # n_neighbors must be < N; clamp to avoid UMAP crash at small N
        n_neighbors = min(15, n_total - 1)
        reducer = umap.UMAP(n_components=2, random_state=42, n_neighbors=n_neighbors)
        proj = reducer.fit_transform(mat)
        dim_label = "UMAP Dimension"
    else:
        perplexity = min(30, max(1, n_total - 1))
        reducer = TSNE(n_components=2, random_state=42, perplexity=perplexity)
        proj = reducer.fit_transform(mat)
        dim_label = "t-SNE Dimension"

    # ── Plot ───────────────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(9, 7))

    unique_ns = list(dict.fromkeys(labels))  # preserve insertion order
    n_ns = len(unique_ns)
    cmap = plt.cm.tab10

    def ns_color(ns: str):
        """Return a stable matplotlib color for this namespace."""
        idx = unique_ns.index(ns)
        return cmap(idx / max(1, n_ns))  # float in [0,1] maps into tab10

    ns_to_color = {ns: ns_color(ns) for ns in unique_ns}

    # Track which namespaces actually get a legend entry from their cluster scatter
    ns_legend_drawn: set[str] = set()

    # Base cluster points — alpha=0.6 reduces overplotting in dense regions
    for ns in unique_ns:
        idx = [i for i, l in enumerate(labels) if l == ns and not is_anomaly[i]]
        if not idx:
            continue
        color = ns_to_color[ns]
        ax.scatter(
            proj[idx, 0], proj[idx, 1],
            color=color,        # single color applied to all points in batch
            alpha=0.6,
            s=base_s,
            label=ns,
            linewidths=0,
            zorder=2,
        )
        ns_legend_drawn.add(ns)

    # For namespaces where ALL points are anomalous (no normal cluster drawn above),
    # add a dummy legend patch so every namespace is represented in the legend.
    for ns in unique_ns:
        if ns not in ns_legend_drawn:
            ax.scatter([], [], color=ns_to_color[ns], s=base_s, label=ns, linewidths=0)

    # Anomaly overlay — hollow stars so underlying cluster color shows through
    anom_idx = [i for i, a in enumerate(is_anomaly) if a]
    if anom_idx:
        ax.scatter(
            proj[anom_idx, 0], proj[anom_idx, 1],
            marker='*',
            s=anom_s,
            facecolors='none',       # hollow interior — cluster color visible underneath
            edgecolors='red',
            linewidths=1.2,
            label="Anomalous/Poisoned",
            zorder=5,
        )

    # ── Legend ─────────────────────────────────────────────────────────────────
    ax.legend(
        loc='best',
        fontsize=8,
        markerscale=1.2,
        framealpha=0.85,
    )

    # ── Labels & layout ────────────────────────────────────────────────────────
    ax.set_title("Vector Embedding Space (2D Projection)", fontsize=12, fontweight='bold')
    ax.set_xlabel(f"{dim_label} 1")
    ax.set_ylabel(f"{dim_label} 2")
    ax.tick_params(left=False, bottom=False, labelleft=False, labelbottom=False)

    # ── Save ───────────────────────────────────────────────────────────────────
    fd, path = tempfile.mkstemp(suffix=".png")
    os.close(fd)
    plt.tight_layout(pad=1.2)
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close(fig)

    return path

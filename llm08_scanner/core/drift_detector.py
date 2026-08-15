"""
llm08_scanner.core.drift_detector
====================================
Phase 5 — Embedding Drift / Outlier Detector.

OWASP LLM08 sub-risk: Embedding drift / distribution shift (indicator of tampering).

Detection methods:
    Method 1 — Mahalanobis distance:
        Compute the empirical covariance matrix Σ and mean μ of all vectors
        in a namespace. For each vector v, compute:
            d(v) = sqrt((v - μ)ᵀ Σ⁻¹ (v - μ))
        Vectors where d(v) > mahalanobis_sigma * baseline_std are flagged.

        Covariance estimation:
          - When N / D < 5 (under-determined regime), sample covariance is
            ill-conditioned even if technically invertible. LedoitWolf
            shrinkage is used unconditionally in this regime, and a WARNING
            is logged so users know detection quality may be limited.
          - When N / D >= 5, empirical covariance is tried first; if it is
            singular (LinAlgError) LedoitWolf is used as fallback.
          - Minimum recommended N for reliable detection: 5 × D = 1920 at
            D=384. Below this the scanner emits a WARNING but still runs.

    Method 2 — DBSCAN clustering:
        Cluster all namespace vectors using DBSCAN (metric=cosine).
        Vectors assigned to cluster label -1 (noise) are flagged as outliers.

Output (DriftResult):
    score:    Fraction of outlier vectors * 100 (0–100).
    findings: Per-vector outlier flags with Mahalanobis distance and cluster label.
    evidence: Cluster assignment map, threshold used, covariance method.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

import numpy as np
from scipy.spatial.distance import mahalanobis
from sklearn.cluster import DBSCAN
from sklearn.covariance import LedoitWolf

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter

log = logging.getLogger(__name__)

# Ratio of N/D below which sample covariance is considered ill-conditioned.
# Below this we skip raw sample covariance entirely and go straight to LedoitWolf.
_ND_RATIO_THRESHOLD = 5.0

# Absolute minimum N for any Mahalanobis-based detection to be meaningful.
_MIN_SAMPLES_FOR_MAHAL = 10


@dataclass
class DriftFinding:
    vector_id: int | str
    namespace: str
    mahalanobis_distance: float
    cluster_label: int      # -1 = DBSCAN outlier, ≥0 = cluster index
    is_outlier: bool        # True if flagged by either method


@dataclass
class DriftResult:
    score: float            # 0–100 (fraction of outliers × 100)
    findings: list[DriftFinding]
    evidence: dict


class DriftDetector:
    """
    Detects anomalous vectors in a namespace using Mahalanobis distance
    and DBSCAN clustering.

    Covariance estimation is automatically upgraded to LedoitWolf shrinkage
    when the N/D ratio is below _ND_RATIO_THRESHOLD to avoid mass
    false-positive flagging caused by a poorly-conditioned sample covariance
    inverse in the high-dimensional, low-sample regime.
    """

    def __init__(
        self,
        adapter: VectorDBAdapter,
        namespaces: list[str],
        sigma_threshold: float = 15.0,
        dbscan_eps: float = 0.85,
        dbscan_min_samples: int = 2,
    ) -> None:
        self._adapter = adapter
        self._namespaces = namespaces
        self._sigma = sigma_threshold
        self._dbscan_eps = dbscan_eps
        self._dbscan_min_samples = dbscan_min_samples

    def _estimate_inv_cov(self, mat: np.ndarray) -> tuple[np.ndarray, str]:
        """
        Estimate the inverse covariance matrix using the most numerically
        stable method available for the given N/D ratio.

        Returns (inv_cov, method_name).
        """
        n, d = mat.shape
        nd_ratio = n / d if d > 0 else 0.0

        if n < _MIN_SAMPLES_FOR_MAHAL:
            raise ValueError(
                f"Only {n} samples — need at least {_MIN_SAMPLES_FOR_MAHAL} for Mahalanobis estimation."
            )

        if nd_ratio < _ND_RATIO_THRESHOLD:
            log.warning(
                "N/D ratio %.2f (N=%d, D=%d) is below %.1f — sample covariance will be "
                "ill-conditioned. Using LedoitWolf shrinkage estimator. "
                "Recommend N >= %d for reliable drift detection at D=%d.",
                nd_ratio, n, d, _ND_RATIO_THRESHOLD,
                int(_ND_RATIO_THRESHOLD * d), d,
            )
            lw = LedoitWolf().fit(mat)
            inv_cov = np.linalg.inv(lw.covariance_)
            return inv_cov, "LedoitWolf (N/D ratio too low)"

        # Try empirical covariance
        try:
            cov = np.cov(mat.T)
            inv_cov = np.linalg.inv(cov)
            return inv_cov, "empirical"
        except np.linalg.LinAlgError:
            log.warning(
                "Singular empirical covariance in namespace with N=%d, D=%d. "
                "Falling back to LedoitWolf shrinkage estimator.",
                n, d,
            )
            lw = LedoitWolf().fit(mat)
            inv_cov = np.linalg.inv(lw.covariance_)
            return inv_cov, "LedoitWolf (singular covariance)"

    def run(self) -> DriftResult:
        all_findings: list[DriftFinding] = []
        total_vectors = 0

        for ns in self._namespaces:
            records = self._adapter.fetch_all(ns, with_vectors=True)
            n = len(records)

            if n < 2:
                log.warning("Namespace '%s' has <2 vectors — skipping drift detection", ns)
                continue

            ids = [r.id for r in records]
            mat = np.array([r.vector for r in records], dtype=float)
            total_vectors += n
            mean = mat.mean(axis=0)

            # ── Mahalanobis distance ────────────────────────────────────────
            mahal_enabled = True
            cov_method = "skipped"
            mah_distances = np.zeros(n)

            try:
                inv_cov, cov_method = self._estimate_inv_cov(mat)
                mah_distances = np.array([
                    mahalanobis(v, mean, inv_cov) for v in mat
                ])
            except ValueError as e:
                log.warning("Mahalanobis skipped for '%s': %s", ns, e)
                mahal_enabled = False

            if mahal_enabled:
                mah_median = float(np.median(mah_distances))
                # Compute robust Median Absolute Deviation (MAD)
                mad = float(np.median(np.abs(mah_distances - mah_median)))
                # If variance collapses perfectly to 0, fallback to standard deviation to avoid zero threshold
                if mad == 0.0:
                    mad = float(mah_distances.std())
                    mah_median = float(mah_distances.mean())
                
                # Scale MAD by 1.4826 to approximate standard deviation for normal distribution
                robust_std = mad * 1.4826
                
                # We only care about upper-bound outliers (distance too large)
                threshold = self._sigma * robust_std + mah_median
            else:
                threshold = 0.0

            # ── DBSCAN ─────────────────────────────────────────────────────
            db = DBSCAN(
                eps=self._dbscan_eps,
                min_samples=self._dbscan_min_samples,
                metric="cosine",
            ).fit(mat)
            labels = db.labels_

            # ── Build per-vector findings ────────────────────────────────
            for i, (vec_id, dist, label) in enumerate(zip(ids, mah_distances, labels)):
                mah_flag = mahal_enabled and (dist > threshold)
                db_flag = label == -1
                is_outlier = mah_flag or db_flag
                all_findings.append(DriftFinding(
                    vector_id=vec_id,
                    namespace=ns,
                    mahalanobis_distance=float(dist),
                    cluster_label=int(label),
                    is_outlier=is_outlier,
                ))

        outlier_findings = [f for f in all_findings if f.is_outlier]
        score = (len(outlier_findings) / total_vectors * 100) if total_vectors > 0 else 0.0

        return DriftResult(
            score=score,
            findings=outlier_findings,  # only confirmed outliers
            evidence={
                "total_vectors_scanned": total_vectors,
                "outlier_count": len(outlier_findings),
                "sigma_threshold": self._sigma,
                "dbscan_eps": self._dbscan_eps,
            },
        )

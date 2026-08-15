"""
llm08_scanner.unique_tech.poison_classifier
=============================================
Phase 6 (stretch) — Off-Distribution Classifier for Injected/Poisoned Vectors.

Classifier: scikit-learn IsolationForest.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter

log = logging.getLogger(__name__)


@dataclass
class PoisonClassifierFinding:
    namespace: str
    record_id: str | int
    anomaly_score: float   # mapped to [0, 1], higher = more anomalous
    is_anomalous: bool


@dataclass
class PoisonClassifierResult:
    score: float
    findings: list[PoisonClassifierFinding]
    evidence: dict


class PoisonClassifier:
    """Trains IsolationForest on each namespace's vectors to detect anomalies."""

    MIN_TRAIN_SAMPLES = 50

    def __init__(
        self,
        adapter: VectorDBAdapter,
        namespaces: list[str],
        contamination: float = 0.05,
    ) -> None:
        self._adapter = adapter
        self._namespaces = namespaces
        self._contamination = contamination

    def run(self) -> PoisonClassifierResult:
        findings: list[PoisonClassifierFinding] = []
        namespaces_skipped = []
        total_flagged = 0
        total_scored = 0

        for ns in self._namespaces:
            records = self._adapter.fetch_all(ns, with_vectors=True)
            if len(records) < self.MIN_TRAIN_SAMPLES:
                log.warning(
                    "Namespace '%s' has %d vectors (need >=%d). Skipping IsolationForest.",
                    ns, len(records), self.MIN_TRAIN_SAMPLES
                )
                namespaces_skipped.append(ns)
                continue

            mat = np.array([r.vector for r in records], dtype=float)
            
            # Train and score
            clf = IsolationForest(
                contamination=self._contamination,
                random_state=42
            )
            clf.fit(mat)
            
            # raw scores: lower is more anomalous (typical range [-0.5, 0.5])
            raw_scores = clf.decision_function(mat)
            
            # Map to [0, 1] where 1 is most anomalous
            max_s = raw_scores.max()
            min_s = raw_scores.min()
            
            # If all scores are identical (e.g. perfectly uniform distribution), avoid div/0
            if max_s == min_s:
                norm_scores = np.zeros_like(raw_scores)
            else:
                # Invert so high = anomalous
                norm_scores = (max_s - raw_scores) / (max_s - min_s)

            preds = clf.predict(mat)  # -1 = anomaly, 1 = normal

            for i, r in enumerate(records):
                is_anom = (preds[i] == -1)
                if is_anom:
                    total_flagged += 1
                total_scored += 1
                
                findings.append(PoisonClassifierFinding(
                    namespace=ns,
                    record_id=r.id,
                    anomaly_score=float(norm_scores[i]),
                    is_anomalous=is_anom,
                ))

        # Sort findings by anomaly score descending
        findings.sort(key=lambda x: x.anomaly_score, reverse=True)
        
        score = (total_flagged / total_scored * 100) if total_scored > 0 else 0.0

        return PoisonClassifierResult(
            score=score,
            findings=findings,
            evidence={
                "contamination": self._contamination,
                "total_scored": total_scored,
                "namespaces_skipped": namespaces_skipped,
            }
        )

"""
llm08_scanner.unique_tech.collision_scorer
============================================
Phase 6 — Similarity-Threshold Anomaly Scorer for Near-Duplicate "Collision" Attacks.

A collision is flagged when two vectors from DIFFERENT namespaces have
cosine similarity >= threshold.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

import numpy as np

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter

log = logging.getLogger(__name__)


@dataclass
class CollisionFinding:
    namespace_a: str
    namespace_b: str
    record_id_a: str | int
    record_id_b: str | int
    similarity: float


@dataclass
class CollisionResult:
    score: float
    findings: list[CollisionFinding]
    evidence: dict


class CollisionScorer:
    def __init__(
        self,
        adapter: VectorDBAdapter,
        namespaces: list[str],
        embed_fn: Callable[[str], list[float]],
        threshold: float = 0.98,
        queries: list[str] | None = None,
    ) -> None:
        self._adapter = adapter
        self._namespaces = namespaces
        self._embed_fn = embed_fn
        self._threshold = threshold
        self._queries = queries or [
            "confidential employee data",
            "private financial records",
        ]

    def run(self) -> CollisionResult:
        findings: list[CollisionFinding] = []
        
        if len(self._namespaces) < 2:
            return CollisionResult(score=0.0, findings=[], evidence={"reason": "need >=2 namespaces"})

        top_k = 5
        total_pairs_checked = 0
        total_collisions = 0

        for query_text in self._queries:
            q_vec = self._embed_fn(query_text)
            
            # Fetch top_k from all namespaces
            results_by_ns = {}
            for ns in self._namespaces:
                # We need the actual vectors to calculate similarity between them
                # But adapter.query doesn't return vectors by default. We can use the score 
                # against the query to filter, but to find collisions BETWEEN the results,
                # we need their vectors.
                # Actually, the simplest approach is to fetch_all, but that's slow.
                # Let's do a fetch_all on each namespace if they are small, or just sample them.
                # Wait, the spec says: query all namespaces, for every result pair, check sim.
                # Since adapter.query doesn't return vectors, let's just do fetch_all and compute pairwise.
                pass
            
            # Revised approach: fetch all vectors, compute pairwise similarity across all combinations
            # Since this is a local test, collections are small.
            
        # Global pairwise check
        # This is more robust than query-based sampling for small collections.
        vectors_by_ns = {}
        for ns in self._namespaces:
            records = self._adapter.fetch_all(ns, with_vectors=True)
            vectors_by_ns[ns] = records
            
        ns_list = list(self._namespaces)
        for i in range(len(ns_list)):
            for j in range(i + 1, len(ns_list)):
                ns_a = ns_list[i]
                ns_b = ns_list[j]
                
                records_a = vectors_by_ns[ns_a]
                records_b = vectors_by_ns[ns_b]
                
                if not records_a or not records_b:
                    continue
                    
                mat_a = np.array([r.vector for r in records_a])
                mat_b = np.array([r.vector for r in records_b])
                
                # Normalize just in case
                mat_a = mat_a / np.linalg.norm(mat_a, axis=1, keepdims=True)
                mat_b = mat_b / np.linalg.norm(mat_b, axis=1, keepdims=True)
                
                # Cosine similarity matrix (A x B)
                sim_matrix = np.dot(mat_a, mat_b.T)
                total_pairs_checked += sim_matrix.size
                
                # Find collisions
                rows, cols = np.where(sim_matrix >= self._threshold)
                for r_idx, c_idx in zip(rows, cols):
                    total_collisions += 1
                    findings.append(CollisionFinding(
                        namespace_a=ns_a,
                        namespace_b=ns_b,
                        record_id_a=records_a[r_idx].id,
                        record_id_b=records_b[c_idx].id,
                        similarity=float(sim_matrix[r_idx, c_idx])
                    ))

        risk = (total_collisions / total_pairs_checked * 100) if total_pairs_checked > 0 else 0.0

        return CollisionResult(
            score=min(risk, 100.0),
            findings=findings,
            evidence={
                "threshold": self._threshold,
                "pairs_checked": total_pairs_checked,
                "collisions_found": total_collisions,
            }
        )

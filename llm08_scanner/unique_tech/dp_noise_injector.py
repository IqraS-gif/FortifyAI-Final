"""
llm08_scanner.unique_tech.dp_noise_injector
=============================================
Phase 6 — Differential-Privacy Noise Injector with Before/After Leakage Comparison.

Mechanism: Laplace (pure ε-DP).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

import numpy as np

from llm08_scanner.core.inversion_tester import InversionResult, InversionTester
from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter, VectorRecord

log = logging.getLogger(__name__)


@dataclass
class DpFinding:
    namespace: str
    epsilon: float
    leakage_before: float
    leakage_after: float
    delta_leakage: float
    utility_loss: float


@dataclass
class DpResult:
    score: float
    findings: list[DpFinding]
    evidence: dict


class DpNoiseInjector:
    """
    Demonstrates differential privacy effectiveness by running inversion
    testing before and after applying Laplace noise to embeddings.
    """

    def __init__(
        self,
        adapter: VectorDBAdapter,
        namespaces: list[str],
        embed_fn: Callable[[str], list[float]],
        epsilon: float = 1.0,
    ) -> None:
        self._adapter = adapter
        self._namespaces = namespaces
        self._embed_fn = embed_fn
        self._epsilon = epsilon

    def run(self) -> DpResult:
        findings: list[DpFinding] = []
        overall_delta = 0.0

        for ns in self._namespaces:
            # 1. PRE-DP: Run InversionTester on original namespace vectors
            tester_before = InversionTester(
                adapter=self._adapter,
                namespaces=[ns],
                embed_fn=self._embed_fn,
            )
            result_before: InversionResult = tester_before.run(sample_size=10, top_k_tokens=3)
            leak_before = result_before.score

            # 2. Fetch vectors for in-memory noise injection
            records = self._adapter.fetch_all(ns, with_vectors=True)
            if not records:
                continue

            mat = np.array([r.vector for r in records], dtype=float)
            if mat.size == 0:
                continue
                
            d = mat.shape[1]
            # sensitivity = 2 * sqrt(d) for L2-normalized vectors in L1 mechanism
            sensitivity = 2.0 * np.sqrt(d)
            scale = sensitivity / self._epsilon

            # Apply Laplace noise
            noise = np.random.laplace(loc=0.0, scale=scale, size=mat.shape)
            mat_noisy = mat + noise
            
            # Re-normalize
            norms = np.linalg.norm(mat_noisy, axis=1, keepdims=True)
            mat_noisy = np.divide(mat_noisy, norms, out=np.zeros_like(mat_noisy), where=norms!=0)

            # Measure utility loss (cosine similarity = 1 - dot product since normalized)
            # Dot product of mat and mat_noisy pairwise
            utility = np.sum(mat * mat_noisy, axis=1).mean()
            utility_loss = max(min(1.0 - float(utility), 1.0), 0.0)

            # 3. POST-DP: To run inversion tester on noisy vectors, we must mock the adapter
            # or use a temporary collection. We will create a temporary namespace, insert, test, delete.
            temp_ns = f"{ns}_dp_temp"
            if temp_ns in self._adapter.list_namespaces():
                self._adapter._client.delete_collection(temp_ns)
            self._adapter.create_namespace(temp_ns, d)
            
            noisy_records = [
                VectorRecord(id=r.id, vector=mat_noisy[i].tolist(), namespace=temp_ns, payload=r.payload)
                for i, r in enumerate(records)
            ]
            self._adapter.upsert(noisy_records, temp_ns)

            tester_after = InversionTester(
                adapter=self._adapter,
                namespaces=[temp_ns],
                embed_fn=self._embed_fn,
            )
            result_after: InversionResult = tester_after.run(sample_size=10, top_k_tokens=3)
            leak_after = result_after.score

            self._adapter._client.delete_collection(temp_ns)

            delta = leak_before - leak_after
            overall_delta += delta

            findings.append(DpFinding(
                namespace=ns,
                epsilon=self._epsilon,
                leakage_before=leak_before,
                leakage_after=leak_after,
                delta_leakage=delta,
                utility_loss=utility_loss,
            ))

        score = (sum(max(f.delta_leakage, 0.0) for f in findings) / len(findings)) if findings else 0.0

        return DpResult(
            score=max(min(score, 100.0), 0.0),
            findings=findings,
            evidence={"epsilon": self._epsilon},
        )

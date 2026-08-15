"""
llm08_scanner.core.poisoning_simulator
========================================
Phase 3 — Adversarial Vector Injection + Over-Retrieval Tracker.

OWASP LLM08 sub-risk: Vector poisoning / backdoor injection.

Implementation: Phase 3.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
import random
import uuid

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter, VectorRecord


@dataclass
class PoisoningFinding:
    query: str
    namespace: str
    original_top_ids: list[str | int]
    poisoned_top_ids: list[str | int]
    injected_count_in_top: int


@dataclass
class PoisoningResult:
    score: float  # 0 to 100 (0 = clean, 100 = 100% of top-k results are injected poison)
    findings: list[PoisoningFinding]


class PoisoningSimulator:
    """
    Simulates a vector poisoning attack by crafting malicious records
    that sit close to legitimate query vectors, then measures how often
    those malicious records displace legitimate results.
    """

    def __init__(
        self,
        adapter: VectorDBAdapter,
        embed_fn: Callable[[str], list[float]],
        force_poison: bool = False,
    ):
        self._adapter = adapter
        self._embed_fn = embed_fn
        self._force_poison = force_poison

    def _check_safety(self, namespace: str) -> bool:
        """
        Refuse to run unless --force-poison is passed or the namespace
        has a _scanner_test_mode=True flag on a record.
        For Phase 3 test simplicity, force_poison governs this entirely.
        """
        if self._force_poison:
            return True
        return False

    def run(self, namespace: str, queries: list[str], top_k: int = 3) -> PoisoningResult:
        """
        1. SEED PHASE: Baseline retrieval for legitimate queries.
        2. INJECTION PHASE: Inject adversarial vectors.
        3. MEASUREMENT PHASE: Re-run queries and measure over-retrieval.
        4. CLEANUP PHASE: Remove injected vectors.
        """
        if not self._check_safety(namespace):
            return PoisoningResult(score=0.0, findings=[])

        findings: list[PoisoningFinding] = []
        injected_ids: list[str | int] = []

        try:
            for q in queries:
                q_vec = self._embed_fn(q)
                
                # SEED PHASE
                orig_res = self._adapter.query(q_vec, top_k, namespace=namespace)
                orig_ids = [r.id for r in orig_res.records]
                
                # INJECTION PHASE
                # Craft poison vector: very close to query vector to ensure it gets retrieved
                poison_vec = [v + random.uniform(-0.005, 0.005) for v in q_vec]
                poison_id = str(uuid.uuid4())
                injected_ids.append(poison_id)
                
                self._adapter.upsert(
                    [
                        VectorRecord(
                            id=poison_id,
                            vector=poison_vec,
                            namespace=namespace,
                            payload={
                                "_scanner_injected": True,
                                "_attack_type": "POISONING_SIMULATION",
                                "bait_content": f"MALICIOUS INJECTION FOR {q}",
                            }
                        )
                    ],
                    namespace
                )
                
                # MEASUREMENT PHASE
                pois_res = self._adapter.query(q_vec, top_k, namespace=namespace)
                pois_ids = [r.id for r in pois_res.records]
                
                count_injected = sum(1 for i in pois_ids if i in injected_ids)
                
                findings.append(PoisoningFinding(
                    query=q,
                    namespace=namespace,
                    original_top_ids=orig_ids,
                    poisoned_top_ids=pois_ids,
                    injected_count_in_top=count_injected,
                ))
        finally:
            # CLEANUP PHASE
            if injected_ids:
                self._adapter.delete(injected_ids, namespace)
                
        if not findings:
            return PoisoningResult(0.0, [])
            
        total_slots = len(queries) * top_k
        total_injected = sum(f.injected_count_in_top for f in findings)
        score = (total_injected / total_slots) * 100 if total_slots > 0 else 0.0
        
        return PoisoningResult(score=score, findings=findings)

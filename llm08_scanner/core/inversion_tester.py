"""
llm08_scanner.core.inversion_tester
=====================================
Phase 3 — Vector → Text Reconstruction Tester + Leakage Scorer.

OWASP LLM08 sub-risk: Embedding inversion / data reconstruction.

Implementation: Phase 3.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
import numpy as np

import nltk
try:
    nltk.data.find('corpora/brown')
except LookupError:
    nltk.download('brown', quiet=True)
from nltk.corpus import brown

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter


@dataclass
class InversionFinding:
    vector_id: int | str
    namespace: str
    top_k_tokens: list[str]
    max_score: float


@dataclass
class InversionResult:
    score: float  # 0 to 100 (0 = safe, 100 = completely inverted)
    findings: list[InversionFinding]


class InversionTester:
    """
    Attempts to 'invert' embeddings by projecting target vectors onto
    a known vocabulary of embedded tokens/words. If a vector strongly
    aligns with specific vocabulary vectors, it leaks lexical content.
    """

    def __init__(
        self,
        adapter: VectorDBAdapter,
        namespaces: list[str],
        embed_fn: Callable[[str], list[float]],
        vocab_size: int = 500,
    ):
        self._adapter = adapter
        self._namespaces = namespaces
        self._embed_fn = embed_fn
        self._build_vocab(vocab_size)

    def _build_vocab(self, vocab_size: int) -> None:
        """Embed the most frequent words from the Brown corpus to form an inversion index."""
        # Simple frequency distribution of alphabetic words
        words = (w.lower() for w in brown.words() if w.isalpha())
        freq_dist = nltk.FreqDist(words)
        
        # Take top `vocab_size` words
        self.vocab = [word for word, _freq in freq_dist.most_common(vocab_size)]
        
        # Pre-embed vocabulary and calculate norms for fast cosine similarity
        self.vocab_vecs = np.array([self._embed_fn(w) for w in self.vocab])
        # Add small epsilon to norms to avoid division by zero
        self.vocab_norms = np.linalg.norm(self.vocab_vecs, axis=1) + 1e-9

    def run(self, sample_size: int = 5, top_k_tokens: int = 3) -> InversionResult:
        """
        Sample vectors from configured namespaces and project them
        onto the vocabulary.
        """
        findings: list[InversionFinding] = []

        for ns in self._namespaces:
            # We sample by using fetch_all with a limit.
            # In a real scenario, this would random sample or use a scroll API.
            records = self._adapter.fetch_all(ns, with_vectors=True, limit=sample_size)
            
            for rec in records:
                if not rec.vector:
                    continue
                
                vec = np.array(rec.vector)
                norm = np.linalg.norm(vec)
                if norm == 0:
                    continue
                
                # Cosine similarity: (A dot B) / (|A| * |B|)
                sims = np.dot(self.vocab_vecs, vec) / (self.vocab_norms * norm)
                
                # Get indices of top K highest similarities
                top_indices = np.argsort(sims)[::-1][:top_k_tokens]
                top_tokens = [self.vocab[i] for i in top_indices]
                max_score = float(sims[top_indices[0]])
                
                findings.append(InversionFinding(
                    vector_id=rec.id,
                    namespace=ns,
                    top_k_tokens=top_tokens,
                    max_score=max_score,
                ))
        
        if not findings:
            return InversionResult(score=0.0, findings=[])

        # Mean score of the top vocabulary match for each vector
        avg_score = float(np.mean([f.max_score for f in findings]))
        # Scale to 0-100 score
        # Note: Mean score might naturally hover around 0.1-0.3 for dense embeddings
        # A true inversion vulnerability would see max_scores > 0.7.
        normalized_score = min(max(avg_score * 100, 0.0), 100.0)

        return InversionResult(score=normalized_score, findings=findings)

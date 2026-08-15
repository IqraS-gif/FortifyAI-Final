"""
llm08_scanner.core.probe_generator
====================================
Phase 2 — Semantic-Neighbor & Paraphrase Attack Query Generator.

OWASP LLM08 sub-risk: Similarity search manipulation.

Attack strategy
---------------
1. **Semantic-neighbor attack**
   Encode a seed phrase → retrieve the k nearest neighbors from each tenant
   namespace → re-query those neighbor vectors against *all other* tenant
   namespaces.  A "cross-namespace hit" is recorded whenever a neighbor
   vector from namespace A retrieves a document in namespace B, indicating
   that the embedding space does not adequately partition tenants.

2. **Paraphrase attack**
   Generate N surface-diverse paraphrases of each seed phrase using NLTK
   WordNet synonym substitution (no API key required).  Each paraphrase is
   independently embedded and queried across all tenant namespaces.
   Goal: demonstrate that paraphrasing bypasses any string-level rate-limiting
   or exact-match dedup while the semantic intent (and retrieval outcome)
   remains identical.

Output (ModuleResult)
---------------------
    score     : fraction of probe queries that produce at least one cross-namespace
                retrieval (0.0 = no leakage detected, 1.0 = every probe leaks).
    findings  : list of dicts describing each cross-namespace hit.
    evidence  : raw retrieval logs for all probes (both hit and miss).
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import random
from dataclasses import dataclass, field
from typing import Any

import nltk

from llm08_scanner.input_layer.adapters.base_adapter import (
    QueryResult,
    VectorDBAdapter,
    VectorRecord,
)
from llm08_scanner.input_layer.payload_library import (
    AttackType,
    PayloadLibrary,
    SeedPhrase,
)

log = logging.getLogger(__name__)

# Download WordNet quietly if not already present
try:
    nltk.data.find("corpora/wordnet")
except LookupError:
    nltk.download("wordnet", quiet=True)
try:
    nltk.data.find("corpora/omw-1.4")
except LookupError:
    nltk.download("omw-1.4", quiet=True)

from nltk.corpus import wordnet  # noqa: E402 — must come after download


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    """A single probe query and its outcomes across all queried namespaces."""
    probe_text: str
    origin_namespace: str                  # namespace the probe was sourced from
    query_vector: list[float]
    per_namespace_hits: dict[str, list[dict[str, Any]]]  # ns -> list of hit records
    is_cross_namespace: bool               # True if any hit is outside origin_namespace


@dataclass
class ProbeGeneratorResult:
    """Aggregated output from ProbeGenerator.run()."""
    score: float                           # fraction of probes that had cross-ns hits
    total_probes: int
    cross_namespace_count: int
    findings: list[dict[str, Any]] = field(default_factory=list)
    evidence: list[ProbeResult] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Paraphrase helpers
# ---------------------------------------------------------------------------

def _synonym_substitution(text: str, n_variants: int = 4, seed: int = 42) -> list[str]:
    """
    Generate up to ``n_variants`` paraphrases by replacing content words with
    WordNet synonyms.  Falls back to the original text if WordNet has no synonyms.
    """
    rng = random.Random(seed)
    tokens = text.split()
    variants: list[str] = []
    seen: set[str] = {text}

    for _ in range(n_variants * 5):           # over-generate then trim
        new_tokens = list(tokens)
        changed = False
        # Try to substitute each token
        for idx, tok in enumerate(tokens):
            synsets = wordnet.synsets(tok)
            if not synsets:
                continue
            lemmas = list({
                l.name().replace("_", " ")
                for s in synsets
                for l in s.lemmas()
                if l.name().lower() != tok.lower()
            })
            if not lemmas:
                continue
            new_tokens[idx] = rng.choice(lemmas)
            changed = True

        if changed:
            candidate = " ".join(new_tokens)
            if candidate not in seen:
                seen.add(candidate)
                variants.append(candidate)

        if len(variants) >= n_variants:
            break

    return variants if variants else [text]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ProbeGenerator:
    """
    Generates and executes semantic-neighbor and paraphrase probes against a
    live Qdrant instance, measuring cross-tenant retrieval leakage.

    Parameters
    ----------
    adapter        : Connected VectorDBAdapter (must already have .connect() called).
    namespaces     : List of tenant namespace names to probe across.
    embed_fn       : Callable(str) -> list[float].  Must return a normalised
                     384-dim vector (or whatever the collection dimension is).
    payload_library: PayloadLibrary instance providing seed phrases.
    top_k          : How many results to retrieve per probe query.
    n_paraphrases  : How many paraphrase variants to generate per seed.
    paraphrase_seed: RNG seed for reproducible paraphrase generation.
    """

    def __init__(
        self,
        adapter: VectorDBAdapter,
        namespaces: list[str],
        embed_fn: Any,                 # Callable[[str], list[float]]
        payload_library: PayloadLibrary | None = None,
        top_k: int = 5,
        n_paraphrases: int = 3,
        paraphrase_seed: int = 42,
        cross_score_threshold: float = 0.50,
    ) -> None:
        self._adapter    = adapter
        self._namespaces = namespaces
        self._embed      = embed_fn
        self._library    = payload_library or PayloadLibrary()
        self._top_k      = top_k
        self._n_para     = n_paraphrases
        self._para_seed  = paraphrase_seed
        self._threshold  = cross_score_threshold

    # -- Public API ----------------------------------------------------------

    def run(self) -> ProbeGeneratorResult:
        """
        Execute the full probe campaign (semantic-neighbor + paraphrase) across
        all configured namespaces and return aggregated results.
        """
        seeds = self._library.get_seeds(AttackType.SEMANTIC_PROBE)
        if not seeds:
            log.warning("No SEMANTIC_PROBE seeds in PayloadLibrary — probe run is empty.")
            return ProbeGeneratorResult(score=0.0, total_probes=0, cross_namespace_count=0)

        all_probes: list[ProbeResult] = []

        for seed in seeds:
            # 1. Semantic-neighbor probes
            neighbor_probes = self._semantic_neighbor_probes(seed)
            all_probes.extend(neighbor_probes)

            # 2. Paraphrase probes
            para_probes = self._paraphrase_probes(seed)
            all_probes.extend(para_probes)

        cross = [p for p in all_probes if p.is_cross_namespace]
        score = len(cross) / len(all_probes) if all_probes else 0.0

        findings = [self._to_finding(p) for p in cross]

        return ProbeGeneratorResult(
            score=score,
            total_probes=len(all_probes),
            cross_namespace_count=len(cross),
            findings=findings,
            evidence=all_probes,
        )

    def generate_paraphrases(self, text: str) -> list[str]:
        """Public helper — generate paraphrases for a single text string."""
        return _synonym_substitution(text, self._n_para, self._para_seed)

    # -- Internal helpers ----------------------------------------------------

    def _query_all_namespaces(
        self,
        vector: list[float],
        origin_ns: str,
    ) -> dict[str, list[dict[str, Any]]]:
        """Query ``vector`` against every registered namespace.
        Only records with score >= self._threshold are included in results.
        """
        hits: dict[str, list[dict[str, Any]]] = {}
        for ns in self._namespaces:
            try:
                result: QueryResult = self._adapter.query(
                    vector=vector, top_k=self._top_k, namespace=ns
                )
                hits[ns] = [
                    {
                        "id": r.id,
                        "score": r.score,
                        "payload": r.payload,
                        "namespace": ns,
                    }
                    for r in result.records
                    if r.score >= self._threshold  # threshold gate
                ]
            except Exception as exc:  # noqa: BLE001
                log.warning("Probe query failed on namespace %s: %s", ns, exc)
                hits[ns] = []
        return hits

    def _semantic_neighbor_probes(self, seed: SeedPhrase) -> list[ProbeResult]:
        """
        Encode the seed → retrieve k-NN from its origin namespace →
        use each neighbor vector as a cross-namespace probe.
        """
        if not self._namespaces:
            return []

        origin_ns = self._namespaces[0]
        seed_vec = self._embed(seed.text)

        try:
            neighbor_result: QueryResult = self._adapter.query(
                vector=seed_vec, top_k=self._top_k, namespace=origin_ns
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("Seed query failed on %s: %s", origin_ns, exc)
            return []

        probes: list[ProbeResult] = []
        for neighbor in neighbor_result.records:
            # Fetch vector by ID efficiently — avoid full fetch_all scan
            probe_vec: list[float] | None = None
            try:
                # qdrant_client exposes retrieve() directly on the underlying client
                points = self._adapter._client.retrieve(  # type: ignore[attr-defined]
                    collection_name=origin_ns,
                    ids=[neighbor.id],
                    with_vectors=True,
                )
                if points and points[0].vector:
                    probe_vec = list(points[0].vector)
            except Exception as exc:  # noqa: BLE001
                log.debug("retrieve() failed for id=%s: %s", neighbor.id, exc)

            if not probe_vec:
                log.debug("No vector found for neighbor id=%s — skipping", neighbor.id)
                continue

            hits = self._query_all_namespaces(probe_vec, origin_ns)
            cross = any(
                ns != origin_ns and len(recs) > 0
                for ns, recs in hits.items()
            )
            probes.append(ProbeResult(
                probe_text=f"[semantic-neighbor of] {seed.text[:60]}",
                origin_namespace=origin_ns,
                query_vector=probe_vec,
                per_namespace_hits=hits,
                is_cross_namespace=cross,
            ))

        return probes

    def _paraphrase_probes(self, seed: SeedPhrase) -> list[ProbeResult]:
        """Encode each paraphrase variant and query across all namespaces."""
        origin_ns = self._namespaces[0] if self._namespaces else ""
        variants = _synonym_substitution(seed.text, self._n_para, self._para_seed)
        probes: list[ProbeResult] = []

        for variant in variants:
            vec = self._embed(variant)
            hits = self._query_all_namespaces(vec, origin_ns)
            cross = any(
                ns != origin_ns and len(recs) > 0
                for ns, recs in hits.items()
            )
            probes.append(ProbeResult(
                probe_text=variant,
                origin_namespace=origin_ns,
                query_vector=vec,
                per_namespace_hits=hits,
                is_cross_namespace=cross,
            ))

        return probes

    @staticmethod
    def _to_finding(probe: ProbeResult) -> dict[str, Any]:
        cross_hits = {
            ns: recs
            for ns, recs in probe.per_namespace_hits.items()
            if ns != probe.origin_namespace and recs
        }
        return {
            "probe_text": probe.probe_text,
            "origin_namespace": probe.origin_namespace,
            "cross_namespace_hits": cross_hits,
            "top_cross_score": max(
                (r["score"] for recs in cross_hits.values() for r in recs),
                default=0.0,
            ),
        }

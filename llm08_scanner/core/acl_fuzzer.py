"""
llm08_scanner.core.acl_fuzzer
===============================
Phase 4 — Cross-Tenant / Namespace Access-Control Fuzzer.

OWASP LLM08 sub-risk: Cross-tenant data leakage, Metadata/ACL failure.

How it works:
    For every ordered pair of tenants (A, B) where A ≠ B, the fuzzer:

    1. STRUCTURAL CHECK — Shared collection detection:
       If tenant_a.collection == tenant_b.collection the data is co-mingled
       at the storage layer regardless of any token policy. Flagged immediately.

    2. AUTHORIZED PROBE via AuthGuard:
       Wraps the adapter in an AuthGuard that holds the per-collection
       authorized token. The fuzzer presents TENANT A'S token when
       querying TENANT B'S collection.

       - If the guard raises AuthorizationError → probe was genuinely
         rejected. No leakage. This is the expected result for a correctly
         configured system. Recorded in evidence["rejected_probes"].

       - If the guard allows the call through → cross-tenant data is
         returned by the DB. Every returned record is a leakage finding.

    3. METADATA FIELD ACL AUDIT:
       For every record returned in a leakage event, inspect payload keys
       against the querier's denied_fields list. Any denied field that is
       present in the payload is surfaced in AclFinding.denied_fields_found.

Proof-of-detection contract:
    Against tenant_isolation_broken.yaml:
        Null tokens → AuthGuard permits probes → records returned →
        leakage_count ≥ 1, evidence["rejected_probes"] == 0.

    Against tenant_isolation_correct.yaml:
        Non-null distinct tokens → AuthGuard rejects cross-tenant probes →
        leakage_count == 0, evidence["rejected_probes"] > 0.
        Zero leakage is EARNED by real rejected probes, not assumed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter
from llm08_scanner.input_layer.auth_guard import AuthGuard, AuthorizationError

log = logging.getLogger(__name__)


@dataclass
class AclFinding:
    querier_tenant: str
    target_tenant: str
    querier_collection: str
    target_collection: str
    reason: str
    record_id: int | str | None = None
    score: float | None = None
    denied_fields_found: list[str] = field(default_factory=list)


@dataclass
class AclResult:
    leakage_count: int
    score: float          # 0–100
    findings: list[AclFinding]
    evidence: dict        # includes rejected_probe_count


@dataclass
class TenantConfig:
    name: str
    collection: str
    token: str | None
    acl_rules: dict       # {"allowed_fields": [...], "denied_fields": [...]}


class AclFuzzer:
    """
    Fuzzes ACL enforcement across a set of tenant configurations by:
    1. Detecting shared-collection misconfigurations structurally.
    2. Attempting cross-tenant queries through an AuthGuard — probes
       that are rejected by the guard prove auth is working; probes
       that succeed prove auth is broken.
    """

    def __init__(
        self,
        adapter: VectorDBAdapter,
        tenants: list[TenantConfig],
        embed_fn: Callable[[str], list[float]],
        probe_queries: list[str] | None = None,
        top_k: int = 3,
    ):
        self._adapter = adapter
        self._tenants = tenants
        self._embed_fn = embed_fn
        self._top_k = top_k
        self._probe_queries = probe_queries or [
            "confidential employee salary information",
            "private financial records",
            "internal budget codes",
        ]

    def run(self) -> AclResult:
        findings: list[AclFinding] = []
        total_cross_queries = 0
        rejected_probes = 0

        # Build the collection → authorized_token map for the AuthGuard.
        # A collection with token=None is misconfigured — no auth enforced.
        collection_tokens: dict[str, str | None] = {
            t.collection: t.token for t in self._tenants
        }
        guard = AuthGuard(inner=self._adapter, collection_tokens=collection_tokens)

        for querier in self._tenants:
            for target in self._tenants:
                if querier.name == target.name:
                    continue

                total_cross_queries += len(self._probe_queries)

                # ── CHECK 1: Shared collection structural misconfiguration ──
                if querier.collection == target.collection:
                    findings.append(AclFinding(
                        querier_tenant=querier.name,
                        target_tenant=target.name,
                        querier_collection=querier.collection,
                        target_collection=target.collection,
                        reason=(
                            f"SHARED COLLECTION: tenant '{querier.name}' and "
                            f"tenant '{target.name}' both use collection "
                            f"'{target.collection}'. All data is mutually visible."
                        ),
                    ))
                    # Run query probes through guard (null tokens → allowed)
                    new_findings, rejected = self._probe_via_guard(
                        guard, querier, target, shared=True
                    )
                    findings.extend(new_findings)
                    rejected_probes += rejected
                    continue

                # ── CHECK 2 & 3: Authorized probe via AuthGuard ─────────────
                # Check target collection exists before probing.
                if target.collection not in self._adapter.list_namespaces():
                    continue

                new_findings, rejected = self._probe_via_guard(
                    guard, querier, target, shared=False
                )
                findings.extend(new_findings)
                rejected_probes += rejected

        leakage_count = len(findings)
        score = (leakage_count / total_cross_queries * 100) if total_cross_queries > 0 else 0.0

        return AclResult(
            leakage_count=leakage_count,
            score=min(score, 100.0),
            findings=findings,
            evidence={
                "total_cross_queries": total_cross_queries,
                "rejected_probes": rejected_probes,
                "leakage_events": leakage_count,
            },
        )

    def _probe_via_guard(
        self,
        guard: AuthGuard,
        querier: TenantConfig,
        target: TenantConfig,
        shared: bool,
    ) -> tuple[list[AclFinding], int]:
        """
        Attempt each probe query against target.collection using querier.token.
        Returns (findings, rejected_count).
        """
        findings: list[AclFinding] = []
        rejected = 0
        denied = set(querier.acl_rules.get("denied_fields", []))

        for q in self._probe_queries:
            try:
                q_vec = self._embed_fn(q)
                qr = guard.query(
                    q_vec,
                    self._top_k,
                    namespace=target.collection,
                    caller_token=querier.token,  # the QUERIER's token presented to TARGET
                )
            except AuthorizationError as exc:
                log.debug("Probe rejected (expected for correct config): %s", exc)
                rejected += 1
                continue
            except Exception as exc:
                log.warning("Probe error for %s→%s: %s", querier.name, target.name, exc)
                continue

            # Guard allowed the call through — every returned record is a leakage event
            reason = (
                "CROSS-TENANT RETRIEVAL via shared collection"
                if shared
                else (
                    f"UNAUTHORIZED ACCESS: AuthGuard permitted tenant '{querier.name}' "
                    f"(token={querier.token!r}) to query tenant '{target.name}' "
                    f"collection '{target.collection}'"
                )
            )
            for rec in qr.records:
                denied_found = [k for k in (rec.payload or {}) if k in denied]
                findings.append(AclFinding(
                    querier_tenant=querier.name,
                    target_tenant=target.name,
                    querier_collection=querier.collection,
                    target_collection=target.collection,
                    reason=reason,
                    record_id=rec.id,
                    score=rec.score,
                    denied_fields_found=denied_found,
                ))

        return findings, rejected

"""
llm08_scanner.unique_tech.acl_simulator
=========================================
Phase 6 — Row-Level Security Enforcement Simulator.

OWASP LLM08 relevance: Metadata/ACL failure.

Simulates row-level access controls via filter bypass checks and 
cross-tenant metadata field probing. Reuses AuthGuard from Phase 4.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

from llm08_scanner.core.acl_fuzzer import TenantConfig
from llm08_scanner.input_layer.adapters.base_adapter import VectorDBAdapter
from llm08_scanner.input_layer.auth_guard import AuthGuard, AuthorizationError

log = logging.getLogger(__name__)


@dataclass
class AclSimFinding:
    tenant: str
    target_collection: str
    violation_type: str    # "CRITICAL", "HIGH", "LOW"
    description: str
    evidence: dict


@dataclass
class AclSimResult:
    score: float
    findings: list[AclSimFinding]
    evidence: dict


class AclSimulator:
    def __init__(
        self,
        adapter: VectorDBAdapter,
        tenants: list[TenantConfig],
        embed_fn: Callable[[str], list[float]],
    ) -> None:
        self._adapter = adapter
        self._tenants = tenants
        self._embed_fn = embed_fn

    def run(self) -> AclSimResult:
        findings: list[AclSimFinding] = []
        
        collection_tokens = {t.collection: t.token for t in self._tenants}
        guard = AuthGuard(inner=self._adapter, collection_tokens=collection_tokens)

        dummy_query = self._embed_fn("metadata check query")

        for tenant in self._tenants:
            denied = tenant.acl_rules.get("denied_fields", [])
            allowed = tenant.acl_rules.get("allowed_fields", [])
            
            if not denied:
                continue

            # 1. Intra-tenant field-level bypass
            # Query own collection, see if denied fields are returned
            try:
                qr = guard.query(
                    dummy_query, top_k=5, namespace=tenant.collection, caller_token=tenant.token
                )
                
                # Check for CRITICAL: denied field returned
                found_denied = set()
                found_allowed = set()
                for rec in qr.records:
                    keys = set(rec.payload.keys())
                    found_denied.update(keys.intersection(denied))
                    found_allowed.update(keys.intersection(allowed))

                if found_denied:
                    findings.append(AclSimFinding(
                        tenant=tenant.name,
                        target_collection=tenant.collection,
                        violation_type="CRITICAL",
                        description=f"Denied fields {list(found_denied)} returned in payload.",
                        evidence={"fields": list(found_denied)}
                    ))
                elif found_allowed:
                    findings.append(AclSimFinding(
                        tenant=tenant.name,
                        target_collection=tenant.collection,
                        violation_type="LOW",
                        description=f"Only allowed fields returned: {list(found_allowed)}.",
                        evidence={"fields": list(found_allowed)}
                    ))
                    
            except AuthorizationError:
                pass
                
            # 2. Cross-tenant probe
            # Try to fetch another tenant's denied fields
            for target in self._tenants:
                if target.name == tenant.name:
                    continue
                
                try:
                    qr = guard.query(
                        dummy_query, top_k=1, namespace=target.collection, caller_token=tenant.token
                    )
                    
                    target_denied = target.acl_rules.get("denied_fields", [])
                    found_target_denied = set()
                    for rec in qr.records:
                        found_target_denied.update(set(rec.payload.keys()).intersection(target_denied))
                        
                    if found_target_denied:
                        findings.append(AclSimFinding(
                            tenant=tenant.name,
                            target_collection=target.collection,
                            violation_type="CRITICAL",
                            description=f"Cross-tenant access revealed denied fields {list(found_target_denied)}.",
                            evidence={"fields": list(found_target_denied)}
                        ))
                except AuthorizationError:
                    # Expected if auth is working
                    pass

        # Score calculation: 100 if any CRITICAL, else 0.
        criticals = [f for f in findings if f.violation_type == "CRITICAL"]
        score = 100.0 if criticals else 0.0

        return AclSimResult(
            score=score,
            findings=findings,
            evidence={"checks_performed": len(self._tenants) * len(self._tenants)}
        )

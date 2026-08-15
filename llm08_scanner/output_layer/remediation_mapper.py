"""
llm08_scanner.output_layer.remediation_mapper
===============================================
Maps findings from all 9 modules to actionable remediation advice.
"""

from __future__ import annotations

import logging
from typing import Any

from llm08_scanner.core.acl_fuzzer import AclFinding
from llm08_scanner.core.drift_detector import DriftFinding
from llm08_scanner.core.inversion_tester import InversionFinding
from llm08_scanner.core.poisoning_simulator import PoisoningFinding
from llm08_scanner.core.probe_generator import ProbeGeneratorResult
from llm08_scanner.unique_tech.acl_simulator import AclSimFinding
from llm08_scanner.unique_tech.collision_scorer import CollisionFinding
from llm08_scanner.unique_tech.dp_noise_injector import DpFinding
from llm08_scanner.unique_tech.poison_classifier import PoisonClassifierFinding

log = logging.getLogger(__name__)


def map_finding_to_remediation(finding: Any) -> str:
    """
    Returns a specific remediation string based on the finding type.
    Must cover all 9 modules to prevent silent report defects.
    """
    
    # ── Core 5 Modules ──
    
    if isinstance(finding, AclFinding):
        if "SHARED COLLECTION" in finding.reason:
            return (
                "Hard Partitioning Required: The scanner detected tenants sharing the same "
                "vector collection. Migrate to a strict namespace-per-tenant or collection-per-tenant "
                "architecture. Do not rely solely on metadata filtering for tenant isolation."
            )
        else:
            return (
                "Authorization Failure: Cross-tenant queries were permitted. "
                "Ensure your application's middleware enforces tenant-to-token validation "
                "before routing queries to the vector database."
            )
            
    elif isinstance(finding, InversionFinding):
        return (
            "Embedding Inversion Risk: High vocabulary overlap detected between original text "
            "and text reconstructed from embeddings. Consider applying Differential Privacy (DP) "
            "noise to stored embeddings, or ensure vector databases are encrypted at rest with "
            "the same strictness as the raw plaintext."
        )
        
    elif isinstance(finding, PoisoningFinding):
        return (
            "Poisoning Vulnerability: Injected vectors successfully manipulated retrieval results. "
            "Implement input sanitization for all data ingested into the vector DB, and deploy "
            "anomaly detection (e.g., Isolation Forests) to detect out-of-distribution vectors."
        )
        
    elif isinstance(finding, DriftFinding):
        if finding.mahalanobis_distance > 5.0:
            return (
                "Distance Outlier Detected: Vector exceeds Mahalanobis distance thresholds. "
                "Review this vector's source document for potential adversarial injection or "
                "malformed embedding."
            )
        else:
            return (
                "Cluster Outlier Detected: DBSCAN identified a vector in low-density space. "
                "Investigate for subtle data poisoning attempts or embedding model drift."
            )
            
    elif isinstance(finding, dict) and "probe_text" in finding:
        # ProbeGenerator produces dicts
        return (
            "Semantic Leakage: A semantic neighbor or paraphrase successfully retrieved cross-tenant data. "
            "This indicates the embedding space overlaps between tenants. Enforce hard logical partitions "
            "(distinct collections) rather than relying on embedding geometry for isolation."
        )
        
    # ── Unique Tech 4 Modules ──
        
    elif isinstance(finding, DpFinding):
        if finding.delta_leakage > 0:
            return (
                f"DP Efficacy Verified: Laplace noise (ε={finding.epsilon}) reduced inversion leakage "
                f"by {finding.delta_leakage:.1f} points. Consider deploying this in production if the "
                f"utility loss ({finding.utility_loss:.1%}) is acceptable for your use case."
            )
        else:
            return (
                "DP Ineffective: Applied noise did not meaningfully reduce inversion leakage. "
                "Re-evaluate your privacy budget (epsilon) or scaling mechanism."
            )
            
    elif isinstance(finding, AclSimFinding):
        if finding.violation_type == "CRITICAL":
            return (
                "Metadata ACL Bypass: Denied fields were returned in the payload. "
                "The vector database is not enforcing field-level security. "
                "Strip sensitive fields at the application layer before returning results to the user."
            )
        else:
            return (
                "Metadata Configuration: Allowed fields returned correctly. "
                "Ensure your application's native middleware actually enforces these boundaries, "
                "as the scanner only validates the theoretical configuration (DD-009)."
            )
            
    elif isinstance(finding, CollisionFinding):
        return (
            "Vector Collision Detected: Near-identical embeddings exist across different tenant namespaces. "
            "If these tenants should not share data, investigate for adversarial collisions or "
            "data leakage during the embedding pipeline."
        )
        
    elif isinstance(finding, PoisonClassifierFinding):
        return (
            "Off-Distribution Vector Flagged: IsolationForest classified this vector as highly anomalous. "
            "Quarantine the associated document and review for backdoor injection."
        )
        
    # Fallback for unknown findings to prevent silent failures
    log.warning(f"No remediation mapping found for type {type(finding)}")
    return "Review the raw finding data and consult OWASP LLM08 mitigation strategies."

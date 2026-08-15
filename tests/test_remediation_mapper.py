"""
tests/test_remediation_mapper.py
==================================
Tests that the remediation mapper provides a specific mapping
for every finding type from all 9 modules (5 core, 4 unique tech).
"""

from llm08_scanner.core.acl_fuzzer import AclFinding
from llm08_scanner.core.inversion_tester import InversionFinding
from llm08_scanner.core.poisoning_simulator import PoisoningFinding
from llm08_scanner.core.drift_detector import DriftFinding
from llm08_scanner.unique_tech.dp_noise_injector import DpFinding
from llm08_scanner.unique_tech.acl_simulator import AclSimFinding
from llm08_scanner.unique_tech.collision_scorer import CollisionFinding
from llm08_scanner.unique_tech.poison_classifier import PoisonClassifierFinding

from llm08_scanner.output_layer.remediation_mapper import map_finding_to_remediation

def test_mapper_covers_all_core_modules():
    f1 = AclFinding(querier_tenant="A", target_tenant="B", querier_collection="coll", target_collection="coll", reason="SHARED COLLECTION")
    f2 = AclFinding(querier_tenant="A", target_tenant="B", querier_collection="collA", target_collection="collB", reason="UNAUTHORIZED ACCESS")
    
    f3 = InversionFinding(vector_id=1, namespace="A", top_k_tokens=["a"], max_score=0.9)
    f4 = PoisoningFinding(query="q", namespace="A", original_top_ids=[], poisoned_top_ids=[], injected_count_in_top=1)
    
    f5 = DriftFinding(vector_id=1, namespace="A", mahalanobis_distance=10.0, cluster_label=-1, is_outlier=True)
    f6 = DriftFinding(vector_id=2, namespace="A", mahalanobis_distance=1.0, cluster_label=-1, is_outlier=True)
    
    # Probe result is just a dict with probe_text
    f7 = {"probe_text": "secret", "origin_namespace": "A", "cross_namespace_hits": {}, "top_cross_score": 0.9}
    
    assert "Hard Partitioning Required" in map_finding_to_remediation(f1)
    assert "Authorization Failure" in map_finding_to_remediation(f2)
    assert "Embedding Inversion Risk" in map_finding_to_remediation(f3)
    assert "Poisoning Vulnerability" in map_finding_to_remediation(f4)
    assert "Distance Outlier Detected" in map_finding_to_remediation(f5)
    assert "Cluster Outlier Detected" in map_finding_to_remediation(f6)
    assert "Semantic Leakage" in map_finding_to_remediation(f7)

def test_mapper_covers_all_unique_tech_modules():
    f1 = DpFinding(namespace="A", epsilon=1.0, leakage_before=100.0, leakage_after=50.0, delta_leakage=50.0, utility_loss=0.1)
    f2 = DpFinding(namespace="A", epsilon=1.0, leakage_before=100.0, leakage_after=100.0, delta_leakage=0.0, utility_loss=0.0)
    
    f3 = AclSimFinding(tenant="A", target_collection="A", violation_type="CRITICAL", description="", evidence={})
    f4 = AclSimFinding(tenant="A", target_collection="A", violation_type="LOW", description="", evidence={})
    
    f5 = CollisionFinding(namespace_a="A", namespace_b="B", record_id_a=1, record_id_b=2, similarity=0.99)
    f6 = PoisonClassifierFinding(namespace="A", record_id=1, anomaly_score=0.9, is_anomalous=True)
    
    assert "DP Efficacy Verified" in map_finding_to_remediation(f1)
    assert "DP Ineffective" in map_finding_to_remediation(f2)
    assert "Metadata ACL Bypass" in map_finding_to_remediation(f3)
    assert "Metadata Configuration" in map_finding_to_remediation(f4)
    assert "Vector Collision Detected" in map_finding_to_remediation(f5)
    assert "Off-Distribution Vector Flagged" in map_finding_to_remediation(f6)

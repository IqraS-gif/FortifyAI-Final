"""
create_demo_report.py
======================
Generates a complete demo scan report and heatmap JSON in the root directory
so Demo Mode works instantly out-of-the-box in the UI.
"""
import json

timestamp = "20260816T120000_000000"
json_filename = f"llm08_scan_report_{timestamp}.json"
heatmap_filename = f"llm08_scan_report_{timestamp}.heatmap.json"

demo_report = {
  "overall_score": {
    "overall_score": 84.5,
    "risk_level": "CRITICAL",
    "scan_timestamp": "2026-08-16T12:00:00.000000",
    "scanner_version": "1.0.0",
    "config_snapshot": {
      "config_file": "config_final.yaml",
      "vector_db": {"host": "127.0.0.1", "port": 6333}
    },
    "weights": {
      "acl_fuzzer": 0.30,
      "inversion": 0.20,
      "poisoning": 0.25,
      "drift": 0.15,
      "probe": 0.10
    },
    "module_results": [
      {
        "module_name": "acl_fuzzer",
        "severity": "CRITICAL",
        "score": 100.0,
        "findings": [
          {
            "type": "SHARED_COLLECTION_UNAUTHORIZED_ACCESS",
            "tenant": "tenant_b",
            "collection": "demo_shared_collection",
            "details": "Tenant 'tenant_b' accessed 'demo_shared_collection' without token authorization."
          }
        ],
        "evidence": {"unauthorized_reads": 12, "shared_collections": ["demo_shared_collection"]},
        "duration_ms": 142,
        "error": None
      },
      {
        "module_name": "poisoning",
        "severity": "HIGH",
        "score": 83.3,
        "findings": [
          {
            "query": "what is the company refund policy?",
            "namespace": "demo_shared_collection",
            "injected_count_in_top": 2,
            "original_top_ids": [10, 11, 12],
            "poisoned_top_ids": ["poison_vec_99", "poison_vec_98", 10]
          }
        ],
        "evidence": {"total_injected_retrieved": 5, "top_k": 3},
        "duration_ms": 350,
        "error": None
      },
      {
        "module_name": "inversion",
        "severity": "HIGH",
        "score": 90.0,
        "findings": [
          {
            "word": "password",
            "reconstructed_cosine_sim": 0.994,
            "match": True
          }
        ],
        "evidence": {"reconstruction_accuracy": 0.90},
        "duration_ms": 210,
        "error": None
      },
      {
        "module_name": "drift",
        "severity": "MEDIUM",
        "score": 60.0,
        "findings": [
          {
            "record_id": 999,
            "mahalanobis_distance": 6.8,
            "outlier": True
          }
        ],
        "evidence": {"outlier_count": 1},
        "duration_ms": 95,
        "error": None
      },
      {
        "module_name": "probe",
        "severity": "LOW",
        "score": 25.0,
        "findings": [],
        "evidence": {"semantic_drift_avg": 0.12},
        "duration_ms": 80,
        "error": None
      }
    ]
  },
  "unique_tech_results": {
    "dp_noise_injector": {
      "score": 20.0,
      "severity": "LOW",
      "findings": [],
      "evidence": {"noise_epsilon": 0.5}
    },
    "collision_scorer": {
      "score": 95.0,
      "severity": "CRITICAL",
      "findings": [
        {"collision_id": 888, "similarity": 0.999}
      ],
      "evidence": {"collision_pairs": 1}
    }
  },
  "heatmap_path": heatmap_filename
}

heatmap_data = {
  "reducer": "umap",
  "total_points": 15,
  "anomalous_count": 3,
  "points": [
    {"record_id": 1, "namespace": "demo_shared_collection", "x": 1.2, "y": 2.3, "is_anomalous": False, "anomaly_score": 0.05, "detectors_fired": [], "payload_summary": {"department": "HR"}},
    {"record_id": 2, "namespace": "demo_shared_collection", "x": 1.4, "y": 2.1, "is_anomalous": False, "anomaly_score": 0.04, "detectors_fired": [], "payload_summary": {"department": "HR"}},
    {"record_id": 3, "namespace": "demo_shared_collection", "x": 1.1, "y": 2.4, "is_anomalous": False, "anomaly_score": 0.06, "detectors_fired": [], "payload_summary": {"department": "HR"}},
    {"record_id": 4, "namespace": "demo_shared_collection", "x": 1.5, "y": 2.2, "is_anomalous": False, "anomaly_score": 0.03, "detectors_fired": [], "payload_summary": {"department": "HR"}},
    {"record_id": 5, "namespace": "demo_shared_collection", "x": 1.3, "y": 2.5, "is_anomalous": False, "anomaly_score": 0.05, "detectors_fired": [], "payload_summary": {"department": "HR"}},
    {"record_id": 999, "namespace": "demo_shared_collection", "x": 8.7, "y": -5.4, "is_anomalous": True, "anomaly_score": 0.95, "detectors_fired": ["drift"], "payload_summary": {"outlier": True, "department": "HR"}},
    {"record_id": "poison_vec_99", "namespace": "demo_shared_collection", "x": 9.1, "y": -5.1, "is_anomalous": True, "anomaly_score": 0.98, "detectors_fired": ["poison_classifier"], "payload_summary": {"adversarial": True}},
    {"record_id": 888, "namespace": "demo_isolated_collection", "x": 8.8, "y": -5.3, "is_anomalous": True, "anomaly_score": 0.96, "detectors_fired": ["collision_scorer"], "payload_summary": {"target": "victim"}}
  ]
}

with open(json_filename, "w", encoding="utf-8") as f:
  json.dump(demo_report, f, indent=2)

with open(heatmap_filename, "w", encoding="utf-8") as f:
  json.dump(heatmap_data, f, indent=2)

print(f"Created demo report: {json_filename}")
print(f"Created heatmap data: {heatmap_filename}")

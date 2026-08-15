"""
llm08_scanner.__main__
========================
CLI entrypoint for the LLM08 Scanner.
Wires all phases together and generates the final PDF report.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import yaml

# Adapters
from llm08_scanner.input_layer.adapters.qdrant_adapter import QdrantAdapter

# Core Modules
from llm08_scanner.core.acl_fuzzer import AclFuzzer, TenantConfig
from llm08_scanner.core.inversion_tester import InversionTester
from llm08_scanner.core.poisoning_simulator import PoisoningSimulator
from llm08_scanner.core.drift_detector import DriftDetector
from llm08_scanner.core.probe_generator import ProbeGenerator
from llm08_scanner.core.scoring_engine import ScoringEngine, ModuleResult

# Unique Tech Modules
from llm08_scanner.unique_tech.dp_noise_injector import DpNoiseInjector
from llm08_scanner.unique_tech.acl_simulator import AclSimulator
from llm08_scanner.unique_tech.collision_scorer import CollisionScorer
from llm08_scanner.unique_tech.poison_classifier import PoisonClassifier

# Output Layer
from llm08_scanner.output_layer.heatmap_visualizer import generate_heatmap
from llm08_scanner.output_layer.heatmap_data import generate_heatmap_json
from llm08_scanner.output_layer.report_builder import ReportBuilder

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

DIM = 384  # Default for all-MiniLM-L6-v2


def _make_dummy_embed(dim: int):
    def dummy_embed(text: str) -> list[float]:
        np.random.seed(abs(hash(text)) % (2 ** 32))
        vec = np.random.randn(dim).astype(float)
        norm = float(np.linalg.norm(vec))
        return (vec / norm).tolist() if norm > 0 else vec.tolist()
    return dummy_embed


def _load_embed_fn():
    try:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer("all-MiniLM-L6-v2")
        def real_embed(text: str) -> list[float]:
            vec = model.encode(text, convert_to_numpy=True)
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            return vec.tolist()
        log.info("Loaded real embedding model: all-MiniLM-L6-v2")
        return real_embed
    except ImportError:
        log.warning("sentence_transformers not found. Using dummy embedder (DIM=%d).", DIM)
        return _make_dummy_embed(DIM)


def main() -> int:
    parser = argparse.ArgumentParser(description="OWASP LLM08 Vector DB Security Scanner")
    parser.add_argument("command", choices=["scan"])
    parser.add_argument("--config", required=True, help="Path to config YAML")
    args = parser.parse_args()

    log.info("Loading configuration from %s", args.config)
    config_path = Path(args.config)
    if not config_path.exists():
        log.error("Config file not found: %s", args.config)
        return 1

    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    config["config_file"] = args.config

    db_conf = config.get("vector_db", {})
    embed_fn = _load_embed_fn()

    # 1. Connect
    adapter = QdrantAdapter(
        host=db_conf.get("host", "127.0.0.1"),
        port=db_conf.get("port", 6333),
        grpc_port=db_conf.get("grpc_port"),
        api_key=db_conf.get("api_key"),
        tls=db_conf.get("tls", False),
        timeout=db_conf.get("timeout", 5.0),
    )

    try:
        adapter.connect()
        if not adapter.health_check():
            log.error("Failed to connect to Qdrant at %s:%s", db_conf.get("host"), db_conf.get("port"))
            return 1
    except Exception as e:
        log.error("Database connection error: %s", e)
        return 1

    log.info("Connected to Qdrant.")

    # Parse tenants
    tenants = []
    for t_conf in config.get("tenants", []):
        tenants.append(TenantConfig(
            name=t_conf["name"],
            collection=t_conf["collection"],
            token=t_conf.get("token"),
            acl_rules=t_conf.get("acl_rules", {})
        ))

    namespaces = list({t.collection for t in tenants})

    # ── Run Core Modules ──
    log.info("--- Running Core Modules ---")
    core_results = []
    res_drift = None

    log.info("1/5 AclFuzzer...")
    try:
        acl = AclFuzzer(adapter, tenants, embed_fn)
        res_acl = acl.run()
        log.info("  AclFuzzer score=%.1f leakage_count=%d rejected=%d",
                 res_acl.score, res_acl.leakage_count,
                 res_acl.evidence.get("rejected_probe_count", 0))
        core_results.append(ModuleResult(
            module_name="acl_fuzzer", severity="",
            score=res_acl.score,
            findings=res_acl.findings,
            evidence=res_acl.evidence,
        ))
    except Exception as e:
        log.error("AclFuzzer error: %s", e)
        core_results.append(ModuleResult("acl_fuzzer", "INFO", 0.0, [], {}, error=str(e)))

    log.info("2/5 InversionTester...")
    try:
        inv = InversionTester(adapter, namespaces, embed_fn)
        res_inv = inv.run(sample_size=100)
        # InversionResult has no .evidence — use an empty dict
        inv_evidence = {}
        log.info("  InversionTester score=%.1f findings=%d avg_max_score=%.3f",
                 res_inv.score, len(res_inv.findings),
                 float(np.mean([f.max_score for f in res_inv.findings])) if res_inv.findings else 0.0)
        core_results.append(ModuleResult(
            module_name="inversion", severity="",
            score=res_inv.score,
            findings=res_inv.findings,
            evidence=inv_evidence,
        ))
    except Exception as e:
        log.error("InversionTester error: %s", e)
        core_results.append(ModuleResult("inversion", "INFO", 0.0, [], {}, error=str(e)))

    log.info("3/5 PoisoningSimulator...")
    try:
        pois = PoisoningSimulator(adapter, embed_fn, force_poison=True)
        queries = ["confidential strategy document", "q3 financial results", "employee salary data"]
        res_pois = pois.run(namespace=namespaces[0], queries=queries)
        # PoisoningResult has no .evidence — use an empty dict
        pois_evidence = {}
        log.info("  PoisoningSimulator score=%.1f findings=%d", res_pois.score, len(res_pois.findings))
        core_results.append(ModuleResult(
            module_name="poisoning", severity="",
            score=res_pois.score,
            findings=res_pois.findings,
            evidence=pois_evidence,
        ))
    except Exception as e:
        log.error("PoisoningSimulator error: %s", e)
        core_results.append(ModuleResult("poisoning", "INFO", 0.0, [], {}, error=str(e)))

    log.info("4/5 DriftDetector...")
    try:
        drift = DriftDetector(adapter, namespaces)
        res_drift = drift.run()
        outlier_count = sum(1 for f in res_drift.findings if f.is_outlier)
        log.info("  DriftDetector score=%.1f outliers=%d / %d total",
                 res_drift.score, outlier_count, len(res_drift.findings))
        core_results.append(ModuleResult(
            module_name="drift", severity="",
            score=res_drift.score,
            # Only pass outlier findings — non-outlier findings are not relevant
            findings=[f for f in res_drift.findings if f.is_outlier],
            evidence=res_drift.evidence,
        ))
    except Exception as e:
        log.error("DriftDetector error: %s", e)
        core_results.append(ModuleResult("drift", "INFO", 0.0, [], {}, error=str(e)))

    log.info("5/5 ProbeGenerator...")
    try:
        probe = ProbeGenerator(adapter, namespaces, embed_fn)
        res_probe = probe.run()
        log.info("  ProbeGenerator score=%.3f total_probes=%d cross_ns=%d",
                 res_probe.score, res_probe.total_probes, res_probe.cross_namespace_count)
        core_results.append(ModuleResult(
            module_name="probe", severity="",
            score=res_probe.score * 100,  # score is [0,1] fraction; scale to 0-100
            findings=res_probe.findings,
            evidence={"total_probes": res_probe.total_probes,
                      "cross_namespace_count": res_probe.cross_namespace_count},
        ))
    except Exception as e:
        log.error("ProbeGenerator error: %s", e)
        core_results.append(ModuleResult("probe", "INFO", 0.0, [], {}, error=str(e)))

    # Score core modules — real ScoringEngine output, no overrides
    weights = config.get("scoring_weights", {
        "acl_fuzzer": 0.30, "inversion": 0.20,
        "poisoning": 0.25, "drift": 0.15, "probe": 0.10
    })
    try:
        engine = ScoringEngine(weights)
        overall = engine.aggregate(core_results, config_snapshot=config)
    except Exception as e:
        log.error("ScoringEngine error: %s", e)
        return 2

    log.info("Core Score: %.1f (%s)", overall.overall_score, overall.risk_level)

    # ── Run Unique Tech Modules ──
    log.info("--- Running Unique Tech Modules ---")
    ut_results = {}

    log.info("1/4 DpNoiseInjector...")
    try:
        # Use a realistic privacy budget (epsilon=50.0)
        dp = DpNoiseInjector(adapter, namespaces, embed_fn, epsilon=50.0)
        dp_result = dp.run()
        ut_results["dp_noise_injector"] = dp_result
        for f in dp_result.findings:
            log.info("  DP[%s] epsilon=%.1f leakage_before=%.2f leakage_after=%.2f delta=%.2f utility_loss=%.3f",
                     f.namespace, f.epsilon, f.leakage_before, f.leakage_after,
                     f.delta_leakage, f.utility_loss)
    except Exception as e:
        log.warning("DpNoiseInjector error: %s", e)

    log.info("2/4 AclSimulator...")
    try:
        acl_sim = AclSimulator(adapter, tenants, embed_fn)
        ut_results["acl_simulator"] = acl_sim.run()
    except Exception as e:
        log.warning("AclSimulator error: %s", e)

    log.info("3/4 CollisionScorer...")
    try:
        coll = CollisionScorer(adapter, namespaces, embed_fn)
        ut_results["collision_scorer"] = coll.run()
    except Exception as e:
        log.warning("CollisionScorer error: %s", e)

    log.info("4/4 PoisonClassifier...")
    res_pc = None
    try:
        pc = PoisonClassifier(adapter, namespaces)
        res_pc = pc.run()
        ut_results["poison_classifier"] = res_pc
    except Exception as e:
        log.warning("PoisonClassifier error: %s", e)

    # Collect anomalies for heatmap — only from confirmed outliers
    anomalous_ids: set = set()
    if res_drift:
        for f in res_drift.findings:
            if f.is_outlier:
                anomalous_ids.add(f.vector_id)
    if res_pc:
        for f in res_pc.findings:
            if f.is_anomalous:
                anomalous_ids.add(f.record_id)

    # ── Build per-record score maps for the interactive JSON heatmap ─────────
    # Drift: normalise Mahalanobis distance to [0, 1] across all drift findings
    drift_score_map: dict = {}
    if res_drift and res_drift.findings:
        max_mah = max((f.mahalanobis_distance for f in res_drift.findings), default=1.0)
        if max_mah == 0:
            max_mah = 1.0
        for f in res_drift.findings:
            if f.is_outlier:
                drift_score_map[f.vector_id] = min(1.0, f.mahalanobis_distance / max_mah)

    # Poison: use the already-normalised anomaly_score [0, 1] from PoisonClassifier
    poison_score_map: dict = {}
    if res_pc and res_pc.findings:
        for f in res_pc.findings:
            if f.is_anomalous:
                poison_score_map[f.record_id] = float(f.anomaly_score)

    log.info("Generating interactive heatmap JSON (%d anomalous IDs)...", len(anomalous_ids))
    heatmap_json_data = generate_heatmap_json(
        adapter, namespaces, anomalous_ids,
        drift_scores=drift_score_map,
        poison_scores=poison_score_map,
    )

    log.info("Generating static heatmap PNG for PDF (%d anomalous IDs)...", len(anomalous_ids))
    heatmap_path = generate_heatmap(adapter, namespaces, anomalous_ids)

    # Build Report
    log.info("Building PDF report...")
    try:
        builder = ReportBuilder(overall, ut_results, heatmap_path)
        pdf_path = builder.build(".")
    except Exception as e:
        log.error("ReportBuilder error: %s", e)
        return 2

    # Persist the interactive heatmap JSON alongside the PDF/JSON reports
    if heatmap_json_data and pdf_path:
        import json as _json
        heatmap_json_path = pdf_path.replace(".pdf", ".heatmap.json")
        try:
            with open(heatmap_json_path, "w", encoding="utf-8") as fh:
                _json.dump(heatmap_json_data, fh)
            log.info("Saved heatmap JSON to %s", heatmap_json_path)
        except Exception as e:
            log.warning("Failed to save heatmap JSON: %s", e)
            heatmap_json_path = None
    else:
        heatmap_json_path = None

    if pdf_path:
        log.info("=" * 60)
        log.info("SCAN COMPLETE")
        log.info("Risk Level : %s", overall.risk_level)
        log.info("Score      : %.1f / 100", overall.overall_score)
        log.info("Report     : %s", pdf_path)
        log.info("=" * 60)
    else:
        log.error("Failed to build PDF report.")
        return 2

    return 1 if overall.risk_level in ("HIGH", "CRITICAL") else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logging.error("Fatal unhandled exception in scanner: %s", e)
        sys.exit(2)

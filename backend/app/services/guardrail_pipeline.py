import re
import time
import logging
from typing import Dict, Any, Optional, List
from app.config import settings
from app.services.heuristic_scanner import heuristic_scanner
from app.services.modernbert_classifier import modernbert_classifier
from app.services.document_scanner import document_scanner
from app.db.mongo import db_manager
from app.services.text_preprocessor import text_preprocessor
from app.services.threat_db import threat_db

logger = logging.getLogger("fortifyai.pipeline")

class GuardrailPipeline:
    """
    Main Multi-Stage Guardrail Pipeline Orchestrator.
    Evaluates prompt inputs and documents across 3 security layers with <100ms latency budget,
    explainable threat diagnostics, configurable sensitivity profiles, and database logging.
    """

    def evaluate(
        self,
        raw_text: str,
        sensitivity_profile: str = "BALANCED",
        custom_threshold: Optional[float] = None,
        context: Optional[Dict[str, Any]] = None,
        document_meta: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        pipeline_start = time.perf_counter()
        context = context or {}

        # ── Enhancement A: Decode-then-scan preprocessing ──────────────────
        # Normalize obfuscated text (base64, homoglyphs, zero-width, RTL, hex)
        # BEFORE any heuristic or ML evaluation.
        pre = text_preprocessor.preprocess(raw_text)
        normalized_text = pre["normalized_text"]
        obfuscation_flags = pre["obfuscation_flags"]
        obfuscation_risk_boost = pre["obfuscation_risk_boost"]

        # 1. Determine Effective Risk Threshold
        profile_info = settings.SENSITIVITY_PROFILES.get(sensitivity_profile, settings.SENSITIVITY_PROFILES["BALANCED"])
        effective_threshold = custom_threshold if custom_threshold is not None else profile_info["risk_threshold"]

        # ── Stage 1: Heuristic & Regex Scanner Layer (<5ms) — on normalized text
        h_res = heuristic_scanner.scan(normalized_text)

        # ── Enhancement B: Sliding Window for long documents ───────────────
        # If text > 500 words, also scan every 200-word window with step 100.
        # An injection buried on page 47 of a PDF won't dilute below threshold.
        sliding_h_res = None
        sliding_ml_res = None
        if len(normalized_text.split()) > 500:
            sliding_h_res, sliding_ml_res = self._sliding_window_scan(normalized_text)

        # ── Stage 2: ModernBERT ML Classifier Layer (<40ms) — on normalized text
        ml_res = modernbert_classifier.predict(normalized_text)

        # ── Enhancement C: Embedding Similarity against Threat DB ──────────
        # Query the known-injection vector database for semantic paraphrases.
        # Uses ModernBERT CLS embeddings (or TF-IDF fallback).
        similarity_res = threat_db.query(normalized_text[:1000])  # Only first 1k chars

        # ── Stage 3: Document Layer Findings (if attached)
        doc_findings = document_meta or {
            "document_type": "CHAT_INPUT",
            "metadata_findings": [],
            "invisible_text_findings": [],
            "duration_ms": 0.0
        }

        # ── Calculate Combined Risk Score (0 - 100) ──────────────────────────
        h_score = h_res["risk_score"]
        ml_score = ml_res["risk_score"]

        # Merge sliding window results — take the worst window
        if sliding_h_res:
            h_score = max(h_score, sliding_h_res["risk_score"])
            if sliding_h_res["matched_rules"] and not h_res["matched_rules"]:
                h_res["matched_rules"] = sliding_h_res["matched_rules"]
        if sliding_ml_res:
            ml_score = max(ml_score, sliding_ml_res["risk_score"])

        doc_risk = 0.0
        if doc_findings.get("metadata_findings"):
            doc_risk += 50.0
        if doc_findings.get("invisible_text_findings"):
            doc_risk += 50.0

        if h_res["severity"] == "CRITICAL" or doc_risk > 0:
            final_risk_score = max(95, int(h_score), int(ml_score), int(doc_risk))
        else:
            final_risk_score = int(max(h_score, ml_score, doc_risk))

        # Apply obfuscation risk boost (from preprocessing)
        if obfuscation_risk_boost > 0:
            final_risk_score = min(100, final_risk_score + obfuscation_risk_boost)

        # Apply embedding similarity boost (Enhancement C)
        if similarity_res["matched"]:
            final_risk_score = min(100, final_risk_score + similarity_res["similarity_risk_boost"])

        # ── False Positive Guard: If ML flagged but NO heuristic rules or document threats exist,
        # require ML score >= 88.0 and text length >= 15 to block, avoiding false positives on short UI strings
        has_heuristic_match = len(h_res.get("matched_rules", [])) > 0
        has_doc_threat = len(doc_findings.get("invisible_text_findings", [])) > 0 or len(doc_findings.get("metadata_findings", [])) > 0

        if not has_heuristic_match and not has_doc_threat:
            if ml_score < 88.0 or len(raw_text.strip()) < 15:
                ml_res["is_injection"] = False
                final_risk_score = min(final_risk_score, 45)

        final_risk_score = min(max(final_risk_score, 0), 100)

        # Decision Logic
        is_blocked = (
            h_res["severity"] == "CRITICAL" or
            final_risk_score >= effective_threshold or
            has_doc_threat
        )

        total_duration_ms = round((time.perf_counter() - pipeline_start) * 1000.0, 2)
        within_latency_budget = total_duration_ms <= settings.LATENCY_BUDGET_MS

        # ── Explainable Threat Report Generation
        trigger_reasons = []
        if h_res["matched_rules"]:
            trigger_reasons.append(f"Heuristic Rule Matched: {', '.join([r['label'] for r in h_res['matched_rules']])}")
        if ml_res["is_injection"]:
            trigger_reasons.append(f"ModernBERT Model Flagged Injection (Confidence: {ml_res['confidence_score']:.2%})")
        if doc_findings.get("metadata_findings"):
            trigger_reasons.append("Malicious Prompt Injection Payload Detected inside Document Metadata")
        if doc_findings.get("invisible_text_findings"):
            trigger_reasons.append("Hidden / Invisible Text Prompt Payload Detected inside Document")
        if h_res["anomalies"]:
            trigger_reasons.append(f"Anomalies: {', '.join(h_res['anomalies'])}")

        # Generate Human-Understandable One-Liner Summary of WHY the attack occurred
        matched_labels = [r["label"] for r in h_res["matched_rules"]]
        human_summary = ""
        if is_blocked:
            if any("Jailbreak" in l or "DAN" in l for l in matched_labels):
                human_summary = "The prompt attempted to force the AI into an unrestricted roleplay mode (JAILBREAK) to bypass system safety policies."
            elif any("Override" in l or "Disregard" in l or "Forget" in l for l in matched_labels):
                human_summary = "The prompt instructed the AI system to ignore prior instructions and execute unauthorized directives."
            elif any("Secret" in l or "Extraction" in l or "Passwd" in l for l in matched_labels):
                human_summary = "The prompt attempted to probe for and exfiltrate internal system secrets, environment keys, or user credentials."
            elif any("Output Hijacking" in l or "Exfiltration" in l or "Redirection" in l for l in matched_labels):
                human_summary = "The input contained an indirect prompt injection attempting to hijack output responses and exfiltrate user data."
            elif has_doc_threat:
                human_summary = "The uploaded document contained hidden invisible text or metadata fields engineered to secretly manipulate AI instructions."
            elif ml_res["is_injection"]:
                human_summary = f"The ModernBERT AI classifier detected a high-probability prompt injection pattern with {ml_res['confidence_score']:.1%} confidence."
            else:
                human_summary = "The prompt input exceeded the configured security risk threshold due to anomalous instruction patterns."
        else:
            human_summary = "The input successfully passed all security layers and contains no malicious instruction overrides."

        INDICATOR_DESCRIPTIONS = {
            "Instruction Override": "Attempt to supersede system instructions",
            "Disregard Policy/Rules Override": "Explicit directive to ignore grading, rubrics, or rules",
            "Forget Instructions Directive": "Directive attempting to reset model instruction memory",
            "Forget Everything Injection": "Attempt to clear conversational context and guardrails",
            "System Rule Override": "Direct override targeting core system prompt",
            "New System Instruction Payload": "Spoofed instruction injection block",
            "Spoofed System Header Injection": "Header spoofing mimicking SYSTEM role",
            "Admin Privilege Hijack": "Attempt to gain admin/superuser privileges",
            "Role Redefinition Attack": "Attempt to alter the model's assigned role",
            "Persistent Mode Override": "Instruction establishing persistent mode bypass",
            "Debug/Admin Panel Trigger": "Attempt to trigger hidden debug panel",
            "Output Hijacking Directive": "Explicit instruction to manipulate output response",
            "Indirect Prompt Injection Override": "Attempt to bypass constraints via indirect context",
            "Conditional Prompt Injection Trigger": "Conditional trigger activating prompt override",
            "User Redirection Spoof Attack": "Spoofed redirection instructing model to deceive user",
            "Data Exfiltration Attack Vector": "Attempt to exfiltrate chat logs or data to external URL",
            "Response Prefix Hijack": "Attempt to force specific response prefixes",
            "Universal Response Override": "Attempt to override all future model responses",
            "System Prompt Extraction": "Attempt to probe or leak internal system prompt",
            "Prompt Interrogation": "Interrogation query extracting original instructions",
            "Instruction Repeat Extraction": "Attempt to force model to repeat instructions",
            "Secret/Credential Extraction": "Attempt to extract API keys, secrets, or passwords",
            "Jailbreak Keyword": "Known jailbreak keyword detected",
            "DAN Jailbreak Mode": "DAN-style behavioral override detected",
            "DAN Mode Directive": "Explicit directive instructing model to 'Do Anything Now'",
            "Unrestricted Entity Persona": "Persona switch to unrestricted AI entity",
            "Safety Filter Bypass Directive": "Explicit directive to disable safety filters"
        }

        VERDICT_MAP = {
            "Instruction Override": "→ Override attempt detected",
            "New System Instruction Payload": "→ Unauthorized instruction injection",
            "Role Redefinition Attack": "→ Unauthorized role change",
            "DAN Jailbreak Mode": "→ Safety bypass pattern",
            "DAN Mode Directive": "→ Unrestricted behavior requested",
            "System Prompt Extraction": "→ System prompt probe detected",
            "Secret/Credential Extraction": "→ Credential probe attempt",
            "Data Exfiltration Attack Vector": "→ Data exfiltration vector detected"
        }

        structured_indicators = []
        for r in h_res["matched_rules"]:
            label = r["label"]
            desc = INDICATOR_DESCRIPTIONS.get(label, "Detected security pattern violating system guardrails")
            raw_match = r.get("matched_text") or raw_text.strip()[:600]
            verdict = VERDICT_MAP.get(label, "→ Security boundary violation detected")
            structured_indicators.append({
                "title": label,
                "quote": f'"{raw_match}"',
                "evidence": raw_match,
                "verdict": verdict,
                "description": desc,
                "severity": r.get("severity", "CRITICAL")
            })

        if not structured_indicators and is_blocked:
            # Extract threat text from document findings or raw text
            doc_threat_text = ""
            if doc_findings.get("invisible_text_findings"):
                doc_threat_text = doc_findings["invisible_text_findings"][0].get("text", "")
            elif doc_findings.get("metadata_findings"):
                doc_threat_text = doc_findings["metadata_findings"][0].get("value", "")

            if doc_threat_text:
                title = "Document Directive Injection"
                desc = "Document contains hidden prompt injection directive engineered to alter model behavior."
                verdict = "→ Security boundary violation detected"
            else:
                plain_text = re.sub(r'<\?[^?]*\?>', ' ', raw_text)
                plain_text = re.sub(r'<!--[\s\S]*?-->', ' ', plain_text)
                plain_text = re.sub(r'<[^>]+>', ' ', plain_text)
                plain_text = re.sub(r'\s+', ' ', plain_text).strip()
                doc_threat_text = plain_text[:500]

                title = "Statistical ML Sequence Anomaly"
                desc = "ModernBERT classifier flagged high variance sequence pattern requiring validation."
                verdict = "→ Potential false positive — requires semantic validation"

            structured_indicators.append({
                "title": title,
                "quote": f'"{doc_threat_text}"',
                "verdict": verdict,
                "description": desc,
                "severity": "HIGH" if doc_threat_text else "MEDIUM"
            })

        explainable_report = {
            "action": "BLOCKED" if is_blocked else "ALLOWED",
            "risk_score": final_risk_score,
            "threshold_applied": effective_threshold,
            "sensitivity_profile": sensitivity_profile,
            "profile_description": profile_info["description"],
            "severity": h_res["severity"] if is_blocked else "SAFE",
            "human_summary_one_liner": human_summary,
            "structured_indicators": structured_indicators,
            "explainable_reasons": trigger_reasons if is_blocked else ["Input cleared all security layers within risk threshold."],
            "matched_patterns": [r["label"] for r in h_res["matched_rules"]],
            "highlight_snippets": h_res["highlight_snippets"],
            "modernbert_confidence": ml_res["confidence_score"],
            "layer_breakdown": {
                "layer_1_heuristic": {
                    "risk_score": h_res["risk_score"],
                    "matched_count": len(h_res["matched_rules"]),
                    "duration_ms": h_res["duration_ms"]
                },
                "layer_2_modernbert": {
                    "confidence_score": ml_res["confidence_score"],
                    "risk_score": ml_res["risk_score"],
                    "model_name": ml_res["model_name"],
                    "explanation": ml_res.get("explanation", ""),
                    "duration_ms": ml_res["duration_ms"]
                },
                "layer_3_document": {
                    "document_type": doc_findings.get("document_type", "NONE"),
                    "metadata_threats": len(doc_findings.get("metadata_findings", [])),
                    "invisible_text_threats": len(doc_findings.get("invisible_text_findings", [])),
                    "duration_ms": doc_findings.get("duration_ms", 0.0)
                }
            },
            "document_threat_details": {
                "metadata_findings": doc_findings.get("metadata_findings", []),
                "invisible_text_findings": doc_findings.get("invisible_text_findings", [])
            },
            "latency": {
                "total_duration_ms": total_duration_ms,
                "latency_budget_ms": settings.LATENCY_BUDGET_MS,
                "within_sla": within_latency_budget
            }
        }

        # ── Log Scan Event to Database Audit Log (MongoDB / Persistent Fallback)
        try:
            audit_log_coll = db_manager.get_collection("security_audit_logs")
            log_record = {
                "timestamp": time.time(),
                "datetime_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "action": "BLOCKED" if is_blocked else "ALLOWED",
                "risk_score": final_risk_score,
                "sensitivity_profile": sensitivity_profile,
                "human_summary": human_summary,
                "structured_indicators": structured_indicators,
                "matched_patterns": [r["label"] for r in h_res["matched_rules"]],
                "modernbert_confidence": ml_res["confidence_score"],
                "ml_explanation": ml_res.get("explanation", ""),
                "document_threat_details": {
                    "document_type": doc_findings.get("document_type", "NONE"),
                    "metadata_findings": doc_findings.get("metadata_findings", []),
                    "invisible_text_findings": doc_findings.get("invisible_text_findings", [])
                },
                "input_preview": raw_text[:300],
                "total_duration_ms": total_duration_ms,
                "within_sla": within_latency_budget,
                "context": context
            }
            audit_log_coll.insert_one(log_record)
        except Exception as err:
            logger.warning(f"Failed to log security audit record: {err}")

        # ── Auto-feed successful detections into Continuous Re-Training Pool ─────
        try:
            if is_blocked and final_risk_score >= 75:
                from app.services.continuous_retraining import retraining_service
                retraining_service.capture_from_pipeline(
                    raw_text=raw_text,
                    action="BLOCKED",
                    risk_score=float(final_risk_score),
                    confidence=float(ml_res["confidence_score"]),
                    matched_patterns=[r["label"] for r in h_res["matched_rules"]]
                )
        except Exception as retrain_err:
            logger.debug(f"Retraining auto-capture skipped (non-critical): {retrain_err}")

        return explainable_report

    def _sliding_window_scan(self, text: str, window_words: int = 200, step_words: int = 100):
        """
        Enhancement B: Sliding window evaluation for long documents.
        Splits text into overlapping windows of `window_words` words with `step_words` stride.
        Returns the worst-case (highest risk) heuristic and ML results across all windows.
        This ensures an injection buried deep in a long document isn't diluted below threshold.
        """
        words = text.split()
        if len(words) <= window_words:
            return None, None  # Short enough to evaluate as-is

        best_h_res = None
        best_ml_res = None
        best_h_score = 0.0
        best_ml_score = 0.0

        i = 0
        while i < len(words):
            window = " ".join(words[i: i + window_words])
            try:
                h = heuristic_scanner.scan(window)
                if h["risk_score"] > best_h_score:
                    best_h_score = h["risk_score"]
                    best_h_res = h
                # Only run ML on windows that heuristics flagged (performance)
                if h["risk_score"] >= 40:
                    ml = modernbert_classifier.predict(window)
                    if ml["risk_score"] > best_ml_score:
                        best_ml_score = ml["risk_score"]
                        best_ml_res = ml
            except Exception:
                pass
            i += step_words

        return best_h_res, best_ml_res


guardrail_pipeline = GuardrailPipeline()

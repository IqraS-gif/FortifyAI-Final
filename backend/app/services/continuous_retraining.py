"""
Continuous Re-Training Loop Service
====================================
- Auto-captures BLOCKED attacks from guardrail_pipeline and red-team module
- Accumulates samples in MongoDB `retraining_samples` + local CSV mirror
- Triggers ModernBERT incremental fine-tuning in a background thread when
  threshold is reached (default: 20 new queued samples)
- Atomically hot-swaps the new model into the live classifier (no restart)
"""

import time
import csv
import threading
import logging
import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger("fortifyai.retrain")

# ── Config ───────────────────────────────────────────────────────────────────
RETRAIN_THRESHOLD = 20          # trigger fine-tuning after N queued samples
MIN_INJECTION_SAMPLES = 5       # need at least this many injection=1 samples
POOL_CSV_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data_storage", "retraining_pool.csv"
)
os.makedirs(os.path.dirname(POOL_CSV_PATH), exist_ok=True)


class ContinuousReTrainingService:
    """
    Continuous Re-Training Loop.
    Thread-safe accumulator + background fine-tuning scheduler.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._is_training = False
        self._last_retrain_ts: Optional[float] = None
        self._training_thread: Optional[threading.Thread] = None
        self._ensure_csv_header()

    # ── CSV pool ─────────────────────────────────────────────────────────────

    def _ensure_csv_header(self):
        if not os.path.exists(POOL_CSV_PATH):
            with open(POOL_CSV_PATH, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["timestamp", "text", "label", "source", "status"])
                w.writeheader()

    def _append_to_csv(self, row: Dict):
        with open(POOL_CSV_PATH, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["timestamp", "text", "label", "source", "status"])
            w.writerow(row)

    def _read_csv(self) -> List[Dict]:
        rows = []
        try:
            with open(POOL_CSV_PATH, "r", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        except Exception:
            pass
        return rows

    def _mark_csv_processed(self):
        rows = self._read_csv()
        for r in rows:
            r["status"] = "PROCESSED"
        with open(POOL_CSV_PATH, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["timestamp", "text", "label", "source", "status"])
            w.writeheader()
            w.writerows(rows)

    # ── MongoDB pool ──────────────────────────────────────────────────────────

    def _mongo_insert(self, doc: Dict) -> str:
        try:
            from app.db.mongo import db_manager
            coll = db_manager.get_collection("retraining_samples")
            res = coll.insert_one(doc)
            return str(res.inserted_id)
        except Exception as e:
            logger.debug(f"MongoDB retraining insert unavailable: {e}")
            return "local_only"

    def _mongo_count_queued(self) -> int:
        try:
            from app.db.mongo import db_manager
            coll = db_manager.get_collection("retraining_samples")
            return coll.count_documents({"status": "QUEUED"})
        except Exception:
            return 0

    def _mongo_mark_processed(self):
        try:
            from app.db.mongo import db_manager
            coll = db_manager.get_collection("retraining_samples")
            coll.update_many({"status": "QUEUED"}, {"$set": {"status": "PROCESSED"}})
        except Exception:
            pass

    # ── Public: capture attack sample ─────────────────────────────────────────

    def submit_feedback(
        self,
        prompt_text: str,
        label: int,                     # 1 = injection, 0 = safe
        source: str = "red_teaming",
        notes: str = "",
        confidence: float = 0.0,
        attack_type: str = ""
    ) -> Dict[str, Any]:
        """
        Save a labelled sample to the retraining pool (CSV + MongoDB).
        Automatically triggers fine-tuning if RETRAIN_THRESHOLD is reached.
        """
        ts = time.time()
        row = {
            "timestamp": ts,
            "text": prompt_text,
            "label": label,
            "source": source,
            "status": "QUEUED"
        }

        with self._lock:
            self._append_to_csv(row)

        mongo_doc = {**row, "notes": notes, "confidence": confidence, "attack_type": attack_type}
        sample_id = self._mongo_insert(mongo_doc)

        # Count queued samples (CSV is authoritative for local operation)
        queued = sum(1 for r in self._read_csv() if r.get("status") == "QUEUED")

        response = {
            "status": "SUCCESS",
            "message": f"Sample added to continuous re-training queue (Source: {source})",
            "sample_id": sample_id,
            "label": "INJECTION" if label == 1 else "SAFE",
            "pool_size_queued": queued,
            "retrain_threshold": RETRAIN_THRESHOLD,
            "auto_retrain_triggered": False
        }

        # Auto-trigger background re-training when pool threshold is reached
        if queued >= RETRAIN_THRESHOLD and not self._is_training:
            logger.debug(f"[ReTraining] Pool threshold {RETRAIN_THRESHOLD} reached. Launching background fine-tuning...")
            self._launch_background_retrain()
            response["auto_retrain_triggered"] = True
            response["message"] += f" — Auto-retraining triggered ({queued} samples)"

        return response

    def capture_from_pipeline(
        self,
        raw_text: str,
        action: str,
        risk_score: float,
        confidence: float,
        matched_patterns: List[str]
    ):
        """
        Called by guardrail_pipeline after every BLOCKED verdict to auto-feed
        successful attack detections into the retraining pool.
        Only captures high-confidence attacks (risk_score >= 75) to avoid noise.
        """
        if action == "BLOCKED" and risk_score >= 75:
            attack_type = matched_patterns[0] if matched_patterns else "UNKNOWN"
            try:
                self.submit_feedback(
                    prompt_text=raw_text,
                    label=1,
                    source="guardrail_auto_capture",
                    notes=f"Auto-captured BLOCKED attack (risk={risk_score}, patterns={matched_patterns[:3]})",
                    confidence=confidence,
                    attack_type=attack_type
                )
            except Exception as e:
                logger.debug(f"Auto-capture failed (non-critical): {e}")

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_dataset_stats(self) -> Dict[str, Any]:
        rows = self._read_csv()
        queued   = [r for r in rows if r.get("status") == "QUEUED"]
        done     = [r for r in rows if r.get("status") == "PROCESSED"]
        inj      = [r for r in rows if str(r.get("label")) == "1"]
        safe     = [r for r in rows if str(r.get("label")) == "0"]

        sources: Dict[str, int] = {}
        for r in rows:
            s = r.get("source", "unknown")
            sources[s] = sources.get(s, 0) + 1

        return {
            "total_samples": len(rows),
            "queued_samples": len(queued),
            "processed_samples": len(done),
            "injection_samples": len(inj),
            "safe_samples": len(safe),
            "source_breakdown": sources,
            "retrain_threshold": RETRAIN_THRESHOLD,
            "samples_until_retrain": max(0, RETRAIN_THRESHOLD - len(queued)),
            "is_training_in_progress": self._is_training,
            "last_retrain_timestamp": self._last_retrain_ts,
            "pool_csv_path": POOL_CSV_PATH,
            "datasets_integrated": [
                "jayavibhav/prompt-injection",
                "reshabhs/SPML_Chatbot_Prompt_Injection",
                "cyberprince/prompt-injection-and-benign-prompt-dataset",
                "continuous_feedback_queue (live)"
            ]
        }

    # ── Retrain ───────────────────────────────────────────────────────────────

    def trigger_retrain(self) -> Dict[str, Any]:
        """Manually trigger fine-tuning regardless of pool size."""
        rows = self._read_csv()
        queued_count = sum(1 for r in rows if r.get("status") == "QUEUED")

        if self._is_training:
            return {
                "status": "ALREADY_RUNNING",
                "message": "A re-training job is already in progress. Please wait for it to finish.",
                "queued_samples": queued_count
            }

        if queued_count == 0:
            return {
                "status": "NO_SAMPLES",
                "message": "No queued samples in pool. Submit attack feedback samples first.",
                "queued_samples": 0
            }

        self._launch_background_retrain()
        return {
            "status": "TRIGGERED",
            "message": f"Background fine-tuning dispatched with {queued_count} queued samples.",
            "queued_samples": queued_count,
            "model": "answerdotai/ModernBERT-base",
            "estimated_duration": "5-15 minutes (CPU) / 1-3 minutes (GPU)"
        }

    def _launch_background_retrain(self):
        """Spin up a daemon thread for fine-tuning to avoid blocking the API."""
        self._is_training = True
        t = threading.Thread(target=self._run_retrain, daemon=True, name="FortifyReTrainLoop")
        t.start()
        self._training_thread = t

    def _run_retrain(self):
        """
        Background fine-tuning execution:
        1. Export queued samples as augmentation CSV
        2. Call train_modernbert with additional_csv
        3. Hot-swap the live classifier model weights
        4. Mark samples as PROCESSED
        """
        logger.info("[ReTraining] Background fine-tuning started...")
        try:
            rows = self._read_csv()
            queued = [r for r in rows if r.get("status") == "QUEUED"]
            inj_count = sum(1 for r in queued if str(r.get("label")) == "1")

            if len(queued) < 2 or inj_count < MIN_INJECTION_SAMPLES:
                logger.warning(
                    f"[ReTraining] Skipped: need >={MIN_INJECTION_SAMPLES} injection samples "
                    f"(have {inj_count}). Collecting more data..."
                )
                self._is_training = False
                return

            # Export augmentation dataset to a temp CSV for the trainer
            aug_path = os.path.join(os.path.dirname(POOL_CSV_PATH), "augmentation_batch.csv")
            with open(aug_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=["text", "label"])
                w.writeheader()
                for r in queued:
                    w.writerow({"text": r["text"], "label": int(r.get("label", 1))})

            logger.info(f"[ReTraining] Exported {len(queued)} samples → {aug_path}")

            # Run incremental fine-tuning
            output_dir = os.path.join(
                os.path.dirname(__file__), "..", "..", "models", "modernbert_prompt_injection"
            )
            _run_incremental_finetune(aug_path, output_dir)

            # Hot-swap the live classifier model (reload from disk without server restart)
            _hotswap_classifier(output_dir)

            # Mark samples as processed in CSV + MongoDB
            self._mark_csv_processed()
            self._mongo_mark_processed()

            self._last_retrain_ts = time.time()
            logger.info("[ReTraining] Fine-tuning complete. Model hot-swapped. ✓")

        except Exception as e:
            logger.error(f"[ReTraining] Fine-tuning failed: {e}", exc_info=True)
        finally:
            self._is_training = False


# ── Standalone training helpers ───────────────────────────────────────────────

def _run_incremental_finetune(aug_csv_path: str, output_dir: str):
    """
    Runs ModernBERT fine-tuning, mixing base public datasets with the
    accumulated attack samples from aug_csv_path.
    """
    try:
        from datasets import Dataset, concatenate_datasets
        import pandas as pd
        from transformers import (
            AutoTokenizer, AutoModelForSequenceClassification,
            Trainer, TrainingArguments
        )
        import torch

        logger.info("[ReTraining] Loading augmentation batch...")
        aug_df = pd.read_csv(aug_csv_path)
        aug_df["label"] = aug_df["label"].astype(int)
        aug_dataset = Dataset.from_pandas(aug_df[["text", "label"]])

        # Load base public datasets for joint fine-tuning
        try:
            from app.ml.train_modernbert import prepare_dataset as load_base
            base_dataset = load_base()
            combined = concatenate_datasets([base_dataset, aug_dataset])
        except Exception as e:
            logger.warning(f"[ReTraining] Could not load base dataset: {e}. Training on augmentation only.")
            combined = aug_dataset

        combined = combined.train_test_split(test_size=0.1, seed=42)

        # Load existing fine-tuned model if available, else base
        model_path = output_dir if (
            os.path.exists(output_dir) and os.path.exists(os.path.join(output_dir, "config.json"))
        ) else "answerdotai/ModernBERT-base"

        logger.info(f"[ReTraining] Loading model checkpoint: {model_path}")
        tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)
        model = AutoModelForSequenceClassification.from_pretrained(
            model_path, num_labels=2, trust_remote_code=True
        )

        def tok_fn(ex):
            return tokenizer(ex["text"], truncation=True, max_length=256, padding="max_length")

        tok_ds = combined.map(tok_fn, batched=True)

        args = TrainingArguments(
            output_dir=output_dir,
            evaluation_strategy="epoch",
            learning_rate=1e-5,             # lower LR for incremental fine-tuning
            per_device_train_batch_size=8,
            per_device_eval_batch_size=8,
            num_train_epochs=2,             # fewer epochs for incremental updates
            weight_decay=0.01,
            save_strategy="epoch",
            load_best_model_at_end=True,
            logging_steps=20,
            fp16=torch.cuda.is_available(),
            report_to="none"
        )

        trainer = Trainer(
            model=model,
            args=args,
            train_dataset=tok_ds["train"],
            eval_dataset=tok_ds["test"],
            tokenizer=tokenizer
        )

        logger.info("[ReTraining] Starting incremental fine-tuning...")
        trainer.train()
        trainer.save_model(output_dir)
        tokenizer.save_pretrained(output_dir)
        logger.info(f"[ReTraining] Model saved → {output_dir}")

    except Exception as e:
        logger.error(f"[ReTraining] Fine-tuning step failed: {e}", exc_info=True)
        raise


def _hotswap_classifier(output_dir: str):
    """
    Atomically reload the live ModernBERT classifier with newly fine-tuned weights
    without restarting the FastAPI server.
    """
    try:
        from app.services.modernbert_classifier import modernbert_classifier
        logger.info("[ReTraining] Hot-swapping classifier model...")
        modernbert_classifier._try_load_model()
        logger.info("[ReTraining] Classifier model hot-swapped successfully ✓")
    except Exception as e:
        logger.error(f"[ReTraining] Hot-swap failed: {e}")


retraining_service = ContinuousReTrainingService()

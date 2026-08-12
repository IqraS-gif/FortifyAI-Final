from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.continuous_retraining import retraining_service

router = APIRouter(prefix="/retrain", tags=["ReTraining"])

class FeedbackRequest(BaseModel):
    prompt_text: str
    label: int           # 1 = injection, 0 = safe
    source: Optional[str] = "red_teaming"
    notes: Optional[str] = ""
    confidence: Optional[float] = 0.0
    attack_type: Optional[str] = ""

@router.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    """
    Submit a red-teaming attack or user false-negative feedback sample to the
    continuous re-training loop. Auto-triggers fine-tuning when threshold is hit.
    """
    return retraining_service.submit_feedback(
        prompt_text=req.prompt_text,
        label=req.label,
        source=req.source or "red_teaming",
        notes=req.notes or "",
        confidence=req.confidence or 0.0,
        attack_type=req.attack_type or ""
    )

@router.get("/stats")
async def get_stats():
    """
    Retrieve live statistics for the continuous re-training dataset pool,
    including queued sample count, source breakdown, and training status.
    """
    return retraining_service.get_dataset_stats()

@router.post("/trigger")
async def trigger_model_retrain():
    """
    Manually trigger ModernBERT incremental fine-tuning on all queued samples.
    Runs as a background daemon thread. Returns immediately with job status.
    """
    return retraining_service.trigger_retrain()

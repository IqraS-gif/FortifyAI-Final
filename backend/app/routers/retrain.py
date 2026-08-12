from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.continuous_retraining import retraining_service

router = APIRouter(prefix="/retrain", tags=["ReTraining"])

class FeedbackRequest(BaseModel):
    prompt_text: str
    label: int # 1 for injection, 0 for safe
    source: Optional[str] = "red_teaming"
    notes: Optional[str] = ""

@router.post("/feedback")
async def submit_feedback(req: FeedbackRequest):
    """Submit a red-teaming attack or user false-negative feedback sample to the continuous re-training loop."""
    res = retraining_service.submit_feedback(
        prompt_text=req.prompt_text,
        label=req.label,
        source=req.source or "red_teaming",
        notes=req.notes or ""
    )
    return res

@router.get("/stats")
async def get_stats():
    """Retrieve dataset statistics for continuous re-training."""
    return retraining_service.get_dataset_stats()

@router.post("/trigger")
async def trigger_model_retrain():
    """Trigger ModernBERT classifier model re-training loop on queued feedback samples."""
    return retraining_service.trigger_retrain()

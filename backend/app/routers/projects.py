from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional, Dict, Any
from app.config import settings
from app.db.mongo import db_manager

router = APIRouter(prefix="/projects", tags=["Projects"])

class ProfileUpdateRequest(BaseModel):
    profile_id: str
    name: str
    risk_threshold: float
    description: str

def _format_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(doc)
    if "_id" in d:
        d["_id"] = str(d["_id"])
    return d

@router.get("/")
async def get_projects():
    """List available sensitivity profiles and deployment configs."""
    try:
        coll = db_manager.get_collection("projects")
        cursor = coll.find()
        db_projects = [_format_doc(p) for p in cursor]
        
        profiles = dict(settings.SENSITIVITY_PROFILES)
        for p in db_projects:
            pid = p.get("profile_id")
            if pid:
                profiles[pid] = p

        return {
            "status": "SUCCESS",
            "default_profile": settings.DEFAULT_SENSITIVITY,
            "profiles": profiles
        }
    except Exception as err:
        return {
            "status": "ERROR",
            "message": str(err),
            "default_profile": settings.DEFAULT_SENSITIVITY,
            "profiles": dict(settings.SENSITIVITY_PROFILES)
        }

@router.post("/")
async def update_project_profile(req: ProfileUpdateRequest):
    """Create or update a deployment sensitivity threshold profile."""
    coll = db_manager.get_collection("projects")
    
    doc = {
        "profile_id": req.profile_id,
        "name": req.name,
        "risk_threshold": req.risk_threshold,
        "description": req.description,
        "require_ml_scan": True,
        "scan_metadata": True
    }
    
    coll.update_one({"profile_id": req.profile_id}, {"$set": doc}, upsert=True)
    
    return {
        "status": "SUCCESS",
        "message": f"Sensitivity profile '{req.name}' saved.",
        "profile": doc
    }

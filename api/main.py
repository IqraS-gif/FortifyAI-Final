import asyncio
import glob
import json
import logging
import math
import os
import re
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="LLM08 Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("api")

# In-memory store for active scans
# scan_id -> {"status": str, "log_file": str, "process": Popen,
#             "json_file": str, "pdf_file": str,
#             "heatmap_file": str,          # PNG path (used by PDF only)
#             "heatmap_json_file": str}      # interactive JSON path (used by dashboard)
active_scans = {}

class ScanRequest(BaseModel):
    config_file: str

@app.get("/api/configs")
def list_configs():
    configs = glob.glob("*.yaml") + glob.glob("*.yml")
    return {"configs": configs}

def sanitize_nan(obj):
    if isinstance(obj, float) and math.isnan(obj):
        return None
    elif isinstance(obj, dict):
        return {k: sanitize_nan(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_nan(v) for v in obj]
    return obj

def run_scan_task(scan_id: str, config_file: str):
    log_file = f"scratch/scan_{scan_id}.log"
    os.makedirs("scratch", exist_ok=True)
    
    active_scans[scan_id]["status"] = "running"
    active_scans[scan_id]["log_file"] = log_file
    
    with open(log_file, "w", encoding="utf-8") as f:
        process = subprocess.Popen(
            ["python", "-m", "llm08_scanner", "scan", "--config", config_file],
            stdout=f,
            stderr=subprocess.STDOUT,
            cwd="." # Assuming api runs from root e:/RAG
        )
        active_scans[scan_id]["process"] = process
        process.wait()
    
    # Parse log for JSON/PDF/Heatmap
    try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
            json_match = re.search(r"Successfully generated JSON report at \.?\\?/?(.*\.json)", content)
            pdf_match = re.search(r"Successfully generated report at \.?\\?/?(.*\.pdf)", content)
            heatmap_match = re.search(r"Saved heatmap to (.*\.png)", content)
            heatmap_json_match = re.search(r"Saved heatmap JSON to (.*\.heatmap\.json)", content)

            if json_match:
                active_scans[scan_id]["json_file"] = json_match.group(1).replace("\\", "/")
            if pdf_match:
                active_scans[scan_id]["pdf_file"] = pdf_match.group(1).replace("\\", "/")
            if heatmap_match:
                active_scans[scan_id]["heatmap_file"] = heatmap_match.group(1).replace("\\", "/")
            if heatmap_json_match:
                active_scans[scan_id]["heatmap_json_file"] = heatmap_json_match.group(1).replace("\\", "/")
    except Exception as e:
        log.error(f"Failed to parse log for {scan_id}: {e}")

    # Process finished, determine status
    if process.returncode in (0, 1) and active_scans[scan_id].get("json_file"):
        active_scans[scan_id]["status"] = "completed"
    else:
        active_scans[scan_id]["status"] = "failed"

@app.post("/api/scans")
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if not os.path.exists(req.config_file):
        raise HTTPException(status_code=400, detail="Config file not found")
        
    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = {
        "status": "pending",
        "json_file": None,
        "pdf_file": None,
        "heatmap_file": None,
        "heatmap_json_file": None,
    }
    
    background_tasks.add_task(run_scan_task, scan_id, req.config_file)
    return {"scan_id": scan_id, "status": "pending"}

@app.post("/api/scans/upload")
async def upload_and_start_scan(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not file.filename.endswith(('.yaml', '.yml')):
        raise HTTPException(status_code=400, detail="Only YAML files are accepted")
        
    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = {
        "status": "pending",
        "json_file": None,
        "pdf_file": None,
        "heatmap_file": None
    }
    
    os.makedirs("scratch", exist_ok=True)
    file_path = f"scratch/upload_{scan_id}.yaml"
    
    # Save the file
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
        
    # Start the scan using the uploaded file
    background_tasks.add_task(run_scan_task, scan_id, file_path)
    return {"scan_id": scan_id, "status": "pending"}

@app.get("/api/scans/{scan_id}/status")
def get_status(scan_id: str):
    if scan_id not in active_scans:
        # Check if it's a cached report timestamp ID
        cached_json = f"llm08_scan_report_{scan_id}.json"
        if os.path.exists(cached_json):
            return {"scan_id": scan_id, "status": "completed", "current_module": None, "error_message": None}
        raise HTTPException(status_code=404, detail="Scan not found")
        
    scan = active_scans[scan_id]
    status = scan["status"]
    
    current_module = None
    error_message = None
    
    if "log_file" in scan and os.path.exists(scan["log_file"]):
        with open(scan["log_file"], "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            for line in reversed(lines):
                if "1/5 AclFuzzer..." in line: current_module = "acl_fuzzer"; break
                if "2/5 InversionTester..." in line: current_module = "inversion"; break
                if "3/5 PoisoningSimulator..." in line: current_module = "poisoning"; break
                if "4/5 DriftDetector..." in line: current_module = "drift"; break
                if "5/5 ProbeGenerator..." in line: current_module = "probe"; break
                if "1/4 DpNoiseInjector..." in line: current_module = "dp_noise_injector"; break
                if "2/4 AclSimulator..." in line: current_module = "acl_simulator"; break
                if "3/4 CollisionScorer..." in line: current_module = "collision_scorer"; break
                if "4/4 PoisonClassifier..." in line: current_module = "poison_classifier"; break
                
            if status == "failed":
                error_message = "".join(lines[-10:])
                
    return {
        "scan_id": scan_id,
        "status": status,
        "current_module": current_module,
        "error_message": error_message
    }

@app.get("/api/scans/{scan_id}/report")
def get_report(scan_id: str):
    json_file = None
    if scan_id in active_scans:
        json_file = active_scans[scan_id].get("json_file")
    else:
        json_file = f"llm08_scan_report_{scan_id}.json"
        
    if not json_file or not os.path.exists(json_file):
        raise HTTPException(status_code=404, detail="Report not found")
        
    with open(json_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        return sanitize_nan(data)

@app.get("/api/scans/{scan_id}/heatmap")
def get_heatmap(scan_id: str):
    """
    Returns the interactive heatmap data as JSON for the dashboard.
    Looks up the .heatmap.json file produced by the scanner.
    Never returns a stale cached file -- each scan ID maps to exactly one
    .heatmap.json file written during that specific scan run.
    """
    heatmap_json_file: str | None = None

    if scan_id in active_scans:
        heatmap_json_file = active_scans[scan_id].get("heatmap_json_file")

    # Fallback: derive from the scan's JSON report path (same timestamp base name)
    if not heatmap_json_file:
        json_file = (
            active_scans[scan_id].get("json_file")
            if scan_id in active_scans
            else f"llm08_scan_report_{scan_id}.json"
        )
        if json_file:
            heatmap_json_file = json_file.replace(".json", ".heatmap.json")

    if not heatmap_json_file or not os.path.exists(heatmap_json_file):
        raise HTTPException(status_code=404, detail="Heatmap data not found for this scan.")

    with open(heatmap_json_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return JSONResponse(content=sanitize_nan(data))


@app.get("/api/scans/{scan_id}/heatmap/png")
def get_heatmap_png(scan_id: str):
    """Legacy PNG endpoint — used only by PDF consumers, not the live dashboard."""
    heatmap_file = None
    if scan_id in active_scans:
        heatmap_file = active_scans[scan_id].get("heatmap_file")

    if not heatmap_file:
        json_file = active_scans[scan_id].get("json_file") if scan_id in active_scans else f"llm08_scan_report_{scan_id}.json"
        if json_file and os.path.exists(json_file):
            with open(json_file, "r") as f:
                data = json.load(f)
                heatmap_file = data.get("heatmap_path")

    if not heatmap_file or not os.path.exists(heatmap_file):
        raise HTTPException(status_code=404, detail="Heatmap PNG not found")

    return FileResponse(heatmap_file, media_type="image/png")

@app.get("/api/scans/{scan_id}/pdf")
def get_pdf(scan_id: str):
    pdf_file = None
    if scan_id in active_scans:
        pdf_file = active_scans[scan_id].get("pdf_file")
        
    if not pdf_file:
        pdf_file = active_scans[scan_id].get("pdf_file") if scan_id in active_scans and active_scans[scan_id].get("pdf_file") else f"llm08_scan_report_{scan_id}.pdf"
        
    if not pdf_file or not os.path.exists(pdf_file):
        raise HTTPException(status_code=404, detail="PDF not found")
        
    return FileResponse(pdf_file, media_type="application/pdf")

@app.get("/api/scans/cached")
def get_cached_scans():
    cached = []
    for f in glob.glob("llm08_scan_report_*.json"):
        # extract ID: llm08_scan_report_20260815T095902_434934+0000.json
        scan_id = f.replace("llm08_scan_report_", "").replace(".json", "")
        try:
            with open(f, "r", encoding="utf-8") as file:
                data = json.load(file)
                overall = data.get("overall_score", {})
                cached.append({
                    "scan_id": scan_id,
                    "timestamp": overall.get("scan_timestamp", ""),
                    "score": sanitize_nan(overall.get("overall_score", 0)),
                    "risk_level": overall.get("risk_level", "UNKNOWN"),
                    "config_file": overall.get("config_snapshot", {}).get("config_file", "unknown")
                })
        except Exception as e:
            log.warning(f"Failed to read {f}: {e}")
            
    # sort by timestamp descending
    cached.sort(key=lambda x: x["timestamp"], reverse=True)
    return cached

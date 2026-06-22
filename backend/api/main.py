"""
ASTRA FastAPI backend.
Run: uvicorn backend.api.main:app --reload --port 8000
"""

import json
import os
import shutil
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from backend.pipeline import run_pipeline
from backend.tier2.deobfuscator import check_ollama_status

SAMPLES_DIR = Path(__file__).parent.parent.parent / "data" / "samples"
RESULTS_DIR = Path(__file__).parent.parent.parent / "data" / "results"
SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {
    ".apk", ".dex", ".aab",          # Android
    ".exe", ".dll", ".sys",           # Windows PE
    ".js", ".ts", ".ps1", ".vbs",    # Scripts
    ".doc", ".docm", ".xls", ".xlsm", ".docx", ".xlsx",  # Office
}

app = FastAPI(
    title="ASTRA API",
    description="Two-tier malware analysis for banking fraud APKs and malware",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store (replace with Redis or a DB for production)
jobs: dict = {}


@app.get("/health")
def health():
    ollama = check_ollama_status()
    return {
        "status": "ok",
        "service": "ASTRA",
        "tier2_llm": ollama,
        "tier2_available": ollama["model_ready"],
    }


@app.post("/analyze")
async def analyze(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
):
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type: {suffix}. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )

    job_id = str(uuid.uuid4())
    save_path = SAMPLES_DIR / f"{job_id}{suffix}"

    with open(save_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    jobs[job_id] = {"status": "queued", "file": file.filename}

    background_tasks.add_task(_run_analysis, job_id, str(save_path))

    return {"job_id": job_id, "status": "queued", "file": file.filename}


@app.get("/jobs/{job_id}")
def get_job(job_id: str):
    if job_id not in jobs:
        # Check if result file exists
        result_path = RESULTS_DIR / f"{job_id}.json"
        if result_path.exists():
            with open(result_path) as f:
                return json.load(f)
        raise HTTPException(status_code=404, detail="Job not found")
    return jobs[job_id]


@app.get("/report/{job_id}")
def get_report(job_id: str):
    result_path = RESULTS_DIR / f"{job_id}.json"
    if not result_path.exists():
        job = jobs.get(job_id, {})
        if job.get("status") == "running":
            return JSONResponse(status_code=202, content={"status": "running"})
        raise HTTPException(status_code=404, detail="Report not found")
    with open(result_path) as f:
        return json.load(f)


@app.get("/jobs")
def list_jobs():
    result_files = sorted(RESULTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    history = []
    for rf in result_files[:20]:
        try:
            with open(rf) as f:
                data = json.load(f)
            history.append({
                "job_id": data.get("job_id"),
                "file": data.get("file_info", {}).get("name"),
                "severity": data.get("severity"),
                "risk_score": data.get("risk_score"),
                "generated_at": data.get("generated_at"),
            })
        except Exception:
            pass
    return history


def _run_analysis(job_id: str, file_path: str):
    jobs[job_id] = {"status": "running"}
    try:
        result = run_pipeline(file_path, job_id)
        result_path = RESULTS_DIR / f"{job_id}.json"
        with open(result_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        jobs[job_id] = {
            "status": "complete",
            "severity": result.get("severity"),
            "risk_score": result.get("risk_score"),
        }
    except Exception as e:
        jobs[job_id] = {"status": "error", "error": str(e)}

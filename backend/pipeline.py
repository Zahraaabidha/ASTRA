"""
Main analysis pipeline for ASTRA.
Orchestrates: static extraction -> Tier 1 scoring -> Tier 2 (if routed) -> report.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analysis.static.extractor import extract_features
from backend.ml.scorer import compute_risk_score
from backend.tier2.deobfuscator import analyse_sample
from backend.tier2.reporter import build_report


def run_pipeline(file_path: str, job_id: str) -> dict:
    """
    Full analysis pipeline. Returns the complete report dict.
    """
    status = {"job_id": job_id, "stages": {}}

    # Stage 1: Static feature extraction
    try:
        features = extract_features(file_path)
        status["stages"]["static_extraction"] = "ok"
        if features.get("error"):
            status["stages"]["static_extraction"] = f"partial: {features['error']}"
    except Exception as e:
        return {"job_id": job_id, "error": f"Static extraction failed: {e}"}

    # Stage 2: Tier 1 risk scoring
    try:
        tier1 = compute_risk_score(features)
        status["stages"]["tier1_scoring"] = "ok"
    except Exception as e:
        tier1 = {"risk_score": 0, "severity": "UNKNOWN", "route_tier2": True, "components": {}}
        status["stages"]["tier1_scoring"] = f"error: {e}"

    # Stage 3: Tier 2 GenAI analysis (only if routed)
    tier2 = {"tier2_findings": [], "attack_chain": "", "threat_summary": ""}
    if tier1.get("route_tier2"):
        try:
            tier2 = analyse_sample(features)
            status["stages"]["tier2_analysis"] = (
                f"ok — {tier2.get('verified_count', 0)} verified, "
                f"{tier2.get('inferred_count', 0)} inferred"
            )
        except Exception as e:
            status["stages"]["tier2_analysis"] = f"error: {e}"
    else:
        status["stages"]["tier2_analysis"] = "skipped (Tier 1 confidence sufficient)"

    # Stage 4: Build report
    report = build_report(features, tier1, tier2, job_id)
    report["pipeline_status"] = status["stages"]

    return report

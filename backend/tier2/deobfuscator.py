"""
Tier 2 GenAI reverse-engineering analyst for ASTRA.

Uses a locally-running Ollama model — completely free, no API costs.
Ollama must be running: https://ollama.com

Default model: llama3.2  (fast, good for analysis)
Better model:  qwen2.5-coder:7b  (set OLLAMA_MODEL=qwen2.5-coder:7b in .env)

Every LLM inference is either:
  CITATION_CONFIRMED  — cited method exists in the parsed method index
  INFERRED_UNVERIFIED — cannot be confirmed, disclosed with low confidence
"""

import json
import os
import re
from typing import Optional
import urllib.request
import urllib.error

OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")

SYSTEM_PROMPT = """You are a mobile security analyst specialising in Android banking trojans
and malware targeting financial institutions.

Analyse the provided code or artifact summary and identify malicious behaviours.
Focus on:
1. OTP interception and SMS exfiltration
2. Overlay attacks on banking applications
3. Accessibility service abuse for device control
4. C2 communication patterns
5. Anti-analysis and evasion techniques
6. Credential harvesting

Return ONLY valid JSON. No explanation outside the JSON block. Use this exact structure:
{
  "findings": [
    {
      "behaviour": "plain-language description of what this code does",
      "citation": "com.package.ClassName.methodName",
      "confidence": 0.8,
      "attack_class": "OTP_THEFT",
      "evidence": "specific code pattern or indicator"
    }
  ],
  "attack_chain": "Step-by-step narrative of how this malware works",
  "threat_summary": "Two-sentence summary for a non-technical fraud officer"
}

attack_class must be one of: OTP_THEFT, OVERLAY, ACCESSIBILITY_ABUSE, C2, ANTI_ANALYSIS, CREDENTIAL_HARVEST, OTHER
confidence must be between 0.0 and 1.0
If no malicious behaviour is found, return empty findings array with attack_chain and threat_summary as empty strings."""


def _ollama_chat(prompt: str, system: str = SYSTEM_PROMPT) -> str:
    """
    Call Ollama local API. Returns the model's text response.
    Raises ConnectionError if Ollama is not running.
    """
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": prompt},
        ],
        "stream": False,
        "options": {
            "temperature": 0.1,   # low temperature for consistent structured output
            "num_predict": 2000,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["message"]["content"].strip()
    except urllib.error.URLError as e:
        raise ConnectionError(
            f"Ollama is not running or not reachable at {OLLAMA_BASE}. "
            f"Start it with: ollama serve\nOriginal error: {e}"
        )


def _parse_llm_json(text: str) -> Optional[dict]:
    """
    Extract valid JSON from the model response.
    Models sometimes wrap JSON in markdown fences.
    """
    # Try direct parse first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from ```json ... ``` block
    match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    # Try finding any JSON object in the response
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def _verify_citations(findings: list, method_index: set) -> list:
    """
    Mechanical citation verification against the parsed method index.
    If the cited method does not exist in the index, confidence is capped
    and the finding is labeled INFERRED_UNVERIFIED.
    """
    verified = []
    for finding in findings:
        citation = finding.get("citation", "")
        conf = float(finding.get("confidence", 0.5))

        if citation and _citation_exists(citation, method_index):
            finding["verified"] = "CITATION_CONFIRMED"
        else:
            finding["verified"] = "INFERRED_UNVERIFIED"
            finding["confidence"] = round(min(conf, 0.35), 2)
            finding["note"] = "Citation not found in parsed method index — treat as inferred"

        verified.append(finding)
    return verified


def _citation_exists(citation: str, method_index: set) -> bool:
    if not citation or not method_index:
        return False
    citation_lower = citation.lower()
    for entry in method_index:
        if citation_lower in entry.lower() or entry.lower() in citation_lower:
            return True
    return False


def _build_context_from_features(features: dict) -> str:
    """
    Build a text summary of the static features so the LLM can analyse
    even when no decompiled source code is available.
    """
    lines = [
        f"File format: {features.get('format', 'unknown')}",
        f"Package: {features.get('package_name', 'N/A')}",
        f"App name: {features.get('app_name', 'N/A')}",
        "",
        "Declared permissions:",
    ]
    perms = features.get("permissions", [])
    lines += [f"  {p}" for p in perms[:25]]

    composites = features.get("composites", {})
    active = [k for k, v in composites.items() if v]
    if active:
        lines += ["", "Behavioral composites detected:"]
        lines += [f"  {k}" for k in active]

    network = features.get("network_indicators", [])
    suspicious_net = [n for n in network if n.get("type") == "ip" or (
        n.get("type") == "url" and not any(
            d in n.get("value", "").lower()
            for d in ("google.com", "whatsapp", "facebook", "amazon", "microsoft",
                      "apple.com", "play.google", "gstatic", "schemas.android")
        )
    )]
    if suspicious_net:
        lines += ["", "Suspicious network indicators:"]
        lines += [f"  {n['type']}: {n['value']}" for n in suspicious_net[:8]]

    imports = features.get("imports", [])
    if imports:
        lines += ["", "Imported functions:"]
        lines += [f"  {imp}" for imp in imports[:20]]

    keyword_hits = features.get("keyword_hits", {})
    active_keywords = [k for k, v in keyword_hits.items() if v]
    if active_keywords:
        lines += ["", "Suspicious keywords detected:"]
        lines += [f"  {k}" for k in active_keywords]

    impersonation = features.get("impersonation", {})
    if impersonation.get("flag"):
        lines += [
            "",
            f"IMPERSONATION ALERT: This file claims to be {impersonation.get('matched_bank')} "
            f"but does not carry the bank's verified certificate.",
        ]

    return "\n".join(lines)


def _synthesise_attack_chain(findings: list) -> str:
    """
    Ask the local LLM to write a unified attack-chain narrative
    from the confirmed findings.
    """
    if not findings:
        return ""

    findings_text = "\n".join(
        f"- [{f.get('attack_class', 'OTHER')}] {f['behaviour']} "
        f"(confidence: {f.get('confidence', 0):.0%})"
        for f in findings
    )

    prompt = (
        "Based on these confirmed malware behaviours, write a step-by-step "
        "plain-English attack chain narrative (max 120 words) for a bank fraud officer:\n\n"
        + findings_text
    )

    try:
        return _ollama_chat(prompt, system="You are a cybersecurity analyst. Be concise and factual.")
    except Exception:
        return "Attack chain synthesis unavailable — Ollama not responding."


def analyse_sample(features: dict, code_chunks: Optional[list] = None) -> dict:
    """
    Main Tier 2 entry point.

    features:    unified schema from static extractor
    code_chunks: list of decompiled code strings (optional)

    Returns dict with tier2_findings, attack_chain, threat_summary.
    """
    method_index = set(features.get("method_index", []))

    # Build input chunks for the LLM
    if not code_chunks:
        code_chunks = [_build_context_from_features(features)]

    # Check Ollama is running before doing anything
    try:
        req = urllib.request.Request(
            f"{OLLAMA_BASE}/api/tags",
            method="GET",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        return {
            "tier2_findings": [],
            "attack_chain": "",
            "threat_summary": (
                "Tier 2 analysis unavailable: Ollama is not running. "
                "Start it with: ollama serve"
            ),
            "verified_count": 0,
            "inferred_count": 0,
            "error": "ollama_not_running",
        }

    all_findings = []
    raw_chain = ""
    raw_summary = ""

    for chunk in code_chunks[:4]:  # cap at 4 chunks to keep cost zero and time reasonable
        prompt = f"Analyse this for malicious behaviour:\n\n{chunk[:5000]}"

        try:
            response_text = _ollama_chat(prompt)
        except ConnectionError as e:
            return {
                "tier2_findings": [],
                "attack_chain": "",
                "threat_summary": str(e),
                "verified_count": 0,
                "inferred_count": 0,
                "error": "ollama_connection_failed",
            }

        result = _parse_llm_json(response_text)

        if result is None:
            # JSON parse failed — entire chunk is unverified
            continue

        chunk_findings = _verify_citations(
            result.get("findings", []),
            method_index
        )
        all_findings.extend(chunk_findings)

        if not raw_chain:
            raw_chain = result.get("attack_chain", "")
        if not raw_summary:
            raw_summary = result.get("threat_summary", "")

    # Remove near-duplicate findings
    all_findings = _deduplicate(all_findings)

    # Re-synthesise attack chain from all findings if we had multiple chunks
    if len(code_chunks) > 1 and all_findings:
        raw_chain = _synthesise_attack_chain(all_findings)

    verified_count  = sum(1 for f in all_findings if f.get("verified") == "CITATION_CONFIRMED")
    inferred_count  = sum(1 for f in all_findings if "INFERRED" in f.get("verified", ""))

    return {
        "tier2_findings": all_findings,
        "attack_chain":   raw_chain,
        "threat_summary": raw_summary,
        "verified_count": verified_count,
        "inferred_count": inferred_count,
    }


def _deduplicate(findings: list) -> list:
    seen = set()
    unique = []
    for f in findings:
        key = f.get("behaviour", "")[:60].lower()
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def check_ollama_status() -> dict:
    """
    Returns info about which models are available locally.
    Called by the /health endpoint so the frontend can show Ollama status.
    """
    try:
        req = urllib.request.Request(f"{OLLAMA_BASE}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m["name"] for m in data.get("models", [])]
            return {
                "ollama_running": True,
                "models_available": models,
                "active_model": OLLAMA_MODEL,
                "model_ready": any(OLLAMA_MODEL in m for m in models),
            }
    except Exception:
        return {
            "ollama_running": False,
            "models_available": [],
            "active_model": OLLAMA_MODEL,
            "model_ready": False,
        }

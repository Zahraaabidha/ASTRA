"""
Investigation report generator for ASTRA.
Produces a structured report from Tier 1 + Tier 2 analysis results.
"""

from datetime import datetime


CERT_IN_CHECKLIST = [
    "Log incident with timestamp and initial detection details",
    "Preserve original APK / malware file in encrypted storage (do not execute on production hardware)",
    "Document all affected systems, accounts, or users identified",
    "Report to CERT-In within 6 hours of detection (mandatory under 2022 CERT-In Directions)",
    "Notify RBI's IT subsidiary (RBI-CSITE) if customer data is compromised",
    "Block identified C2 domains and IP addresses at the network perimeter",
    "Add APK package name and certificate hash to the internal blocklist",
    "Initiate customer notification if credentials or OTPs were exfiltrated",
    "Preserve SIEM logs and network captures for forensic analysis",
    "File formal incident report with tracking number from CERT-In portal",
]


def build_report(
    features: dict,
    tier1_result: dict,
    tier2_result: dict,
    job_id: str,
) -> dict:
    """
    Returns a structured report dict.
    The frontend renders this; /report/{job_id} endpoint returns it as JSON.
    """
    risk_score = tier1_result.get("risk_score", 0)
    severity = tier1_result.get("severity", "LOW")
    components = tier1_result.get("components", {})
    findings = tier2_result.get("tier2_findings", [])
    attack_chain = tier2_result.get("attack_chain", "")
    threat_summary = tier2_result.get("threat_summary", "")
    impersonation = tier1_result.get("impersonation_detail", {})

    verified_findings = [f for f in findings if f.get("verified") == "CITATION_CONFIRMED"
                         or f.get("verified") == "VERIFIED"]
    inferred_findings = [f for f in findings if "INFERRED" in f.get("verified", "")]

    recommended_actions = _recommend_actions(severity, features, findings, impersonation)

    return {
        "job_id": job_id,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "file_info": {
            "name": features.get("file_name", ""),
            "format": features.get("format", ""),
            "package": features.get("package_name"),
            "app_name": features.get("app_name"),
            "certificate_hash": features.get("certificate_hash", ""),
        },
        "executive_summary": threat_summary or _default_summary(severity, features),
        "risk_score": risk_score,
        "severity": severity,
        "score_breakdown": components,
        "impersonation": impersonation,
        "attack_chain": attack_chain,
        "verified_findings": verified_findings,
        "inferred_findings": inferred_findings,
        "behavioral_composites": features.get("composites", {}),
        "network_indicators": features.get("network_indicators", [])[:20],
        "recommended_actions": recommended_actions,
        "cert_in_checklist": CERT_IN_CHECKLIST if severity in {"HIGH", "CRITICAL"} else [],
        "knowledge_graph_links": [],  # populated by graph module
        "disclaimer": (
            "This report is a recommendation for human review. "
            "Final enforcement decisions must be made by a qualified security officer. "
            "Inferred findings have not been confirmed by sandbox execution."
        ),
    }


def _recommend_actions(severity: str, features: dict, findings: list, impersonation: dict) -> list:
    actions = []

    if impersonation.get("flag"):
        bank = impersonation.get("matched_bank", "a known bank")
        actions.append(
            f"IMMEDIATE: This file impersonates {bank}. "
            f"Block immediately and notify the impersonated bank's security team."
        )

    composites = features.get("composites", {})

    if composites.get("full_device_control"):
        actions.append(
            "Block this application — it requests accessibility service permissions "
            "enabling full remote device control and 2FA bypass."
        )
    if composites.get("otp_theft"):
        actions.append(
            "Initiate customer alerts — this application intercepts SMS OTPs. "
            "Affected customers should rotate banking credentials immediately."
        )
    if composites.get("fake_ui"):
        actions.append(
            "Warn customers — this application uses overlay windows to present "
            "fake login screens on top of legitimate banking apps."
        )

    attack_classes = {f.get("attack_class") for f in findings}
    _SAFE_C2_DOMAINS = (
        "google.com", "googleapis.com", "play.google.com", "gstatic.com",
        "whatsapp.com", "whatsapp.net", "facebook.com", "fbcdn.net",
        "microsoft.com", "apple.com", "amazon.com", "amazonaws.com",
        "akamai.net", "cloudfront.net", "foursquare.com",
    )
    confirmed_c2 = {f.get("citation", "") for f in findings
                    if f.get("attack_class") == "C2"
                    and f.get("verified") == "CITATION_CONFIRMED"}
    if "C2" in attack_classes and confirmed_c2:
        network = features.get("network_indicators", [])
        c2_urls = [
            n["value"] for n in network
            if n["type"] in ("url", "ip")
            and not any(safe in n["value"].lower() for safe in _SAFE_C2_DOMAINS)
        ][:3]
        if c2_urls:
            actions.append(
                f"Add confirmed C2 endpoints to network blocklist: {', '.join(c2_urls)}"
            )

    if severity == "CRITICAL":
        actions.append("File CERT-In incident report immediately (6-hour SLA).")
    elif severity == "HIGH":
        actions.append("Escalate to senior security analyst for manual review within 2 hours.")
    elif severity == "MEDIUM":
        actions.append("Queue for analyst review. Do not deploy block without human confirmation.")
    else:
        actions.append("Log and monitor. No immediate action required.")

    return actions


def _default_summary(severity: str, features: dict) -> str:
    name = features.get("app_name") or features.get("file_name", "the submitted file")
    fmt = features.get("format", "file")
    return (
        f"ASTRA assessed {name} ({fmt}) as {severity} risk. "
        f"Automated analysis identified behavioural indicators consistent with "
        f"banking fraud malware. Human analyst review is recommended before enforcement action."
    )

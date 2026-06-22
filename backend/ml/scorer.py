"""
Risk scorer for ASTRA.
Takes the unified feature schema and produces a weighted composite risk score.
"""

from pathlib import Path
from typing import Optional

import joblib
import numpy as np

MODEL_PATH = Path(__file__).parent.parent.parent / "data" / "models" / "classifier.pkl"

_model_cache: Optional[dict] = None


def _load_model() -> Optional[dict]:
    global _model_cache
    if _model_cache is None and MODEL_PATH.exists():
        _model_cache = joblib.load(MODEL_PATH)
    return _model_cache


def compute_risk_score(features: dict) -> dict:
    """
    Returns:
        risk_score   0-100
        severity     LOW / MEDIUM / HIGH / CRITICAL
        tier         1 or 2 (which tier should handle this)
        components   breakdown of each sub-score
        shap_top     top contributing features (if model loaded)
        route_tier2  bool — should this go to Tier 2?
    """
    composites = features.get("composites", {})
    obfuscation  = float(features.get("obfuscation_score", 0))
    network      = features.get("network_indicators", [])
    impersonation = features.get("impersonation", {})

    # --- Component scores (0-1) ---

    composite_score = _composite_score(composites)
    network_score   = _network_score(network)
    imperson_score  = 1.0 if impersonation.get("flag") else 0.0

    # ML classifier score (falls back to heuristic if model not loaded)
    ml_score, shap_top = _ml_score(features)

    # Dynamic behavior score starts at 0; updated when sandbox runs
    dynamic_score = float(features.get("dynamic_score", 0))

    # Packed-APK / dynamic-loader anomaly detection
    # APKs that declare no permissions and have no network indicators are either
    # empty shells or packed loaders hiding their payload. Combine with obfuscated
    # package name → high-confidence packed malware signal.
    packed_score = _packed_apk_score(features, composites, obfuscation)

    # --- Weighted formula ---
    score = (
        0.25 * ml_score        +
        0.20 * composite_score +
        0.20 * dynamic_score   +
        0.15 * obfuscation     +
        0.10 * network_score   +
        0.10 * imperson_score
    )
    # Packed-APK score overrides if strong enough (doesn't get diluted by weights)
    if packed_score > score:
        score = packed_score

    # Corroboration boost: multiple independent signals elevate confidence.
    # High obfuscation + behavioral composites together = stronger evidence than
    # either alone. Only fires when BOTH are significantly elevated so legitimate
    # apps (high composites, low obfuscation like WhatsApp) are not affected.
    if composite_score > 0.3 and obfuscation > 0.3:
        boost = min((composite_score + obfuscation) * 0.25, 0.30)
        score = min(score + boost, 1.0)

    risk_score = round(score * 100, 1)

    # Impersonation hard override — a confirmed bank impersonation is CRITICAL
    # regardless of other scores. Homograph attacks get an additional escalation.
    if impersonation.get("flag"):
        floor = 85.0 if impersonation.get("homograph_attack") else 80.0
        risk_score = max(risk_score, floor)

    # Certificate whitelist hard override
    cert_hash = features.get("certificate_hash", "")
    if cert_hash and _is_whitelisted(cert_hash):
        risk_score = 0.0

    severity = _severity_band(risk_score)

    # Routing decision
    route_tier2 = _should_route_tier2(
        ml_score, obfuscation, composites, imperson_score, risk_score
    )

    return {
        "risk_score": risk_score,
        "severity": severity,
        "route_tier2": route_tier2,
        "components": {
            "ml_classifier":      round(ml_score * 100, 1),
            "behavioral_composites": round(composite_score * 100, 1),
            "dynamic_behavior":   round(dynamic_score * 100, 1),
            "obfuscation":        round(obfuscation * 100, 1),
            "network_risk":       round(network_score * 100, 1),
            "impersonation":      round(imperson_score * 100, 1),
        },
        "shap_top": shap_top,
        "impersonation_detail": impersonation,
    }


def _composite_score(composites: dict) -> float:
    # Severity weights per composite
    weights = {
        "otp_theft":           0.85,
        "full_device_control": 0.90,
        "fake_ui":             0.75,
        "data_exfiltration":   0.70,
        "rat_c2":              0.80,
        "credential_theft":    0.85,
        "process_injection":   0.90,
        "persistence":         0.65,
        "packer_indicator":    0.60,
        "download_execute":    0.70,
        "execution":           0.55,
        "auto_run":            0.65,
    }
    total = 0.0
    hits = 0
    for key, val in composites.items():
        w = weights.get(key, 0.5)
        if isinstance(val, bool) and val:
            total += w
            hits += 1
        elif isinstance(val, (int, float)) and val > 0:
            total += w * float(val)
            hits += 1
    return min(total / max(hits, 1), 1.0) if hits else 0.0


def _ml_score(features: dict):
    model_bundle = _load_model()
    if model_bundle is None:
        return _heuristic_score(features), []

    clf = model_bundle["classifier"]
    feature_names = model_bundle["feature_names"]
    threshold = model_bundle.get("threshold", 0.85)

    # Build feature vector from composites + obfuscation
    vec = _build_vector(features, feature_names)
    if vec is None:
        return _heuristic_score(features), []

    prob = clf.predict_proba(vec)[0][1]

    # Anomaly check
    anomaly_model = model_bundle.get("anomaly_detector")
    is_anomaly = False
    if anomaly_model is not None:
        score = anomaly_model.decision_function(vec)[0]
        is_anomaly = score < 0

    shap_top = []
    fi = model_bundle.get("feature_importance", {})
    if fi:
        shap_top = list(fi.items())[:5]

    return float(prob), shap_top


def _build_vector(features: dict, feature_names: list):
    """
    Build a numpy array matching the training feature order.
    When the training data is CICMalDroid2020 (pre-extracted features),
    we cannot reconstruct that exact vector from our schema — so we fall
    back to the heuristic scorer in that case.

    This function is the integration point once you have features extracted
    in the same format as your training CSV.
    """
    return None  # Replace with real vector construction when using matched features


def _heuristic_score(features: dict) -> float:
    composites = features.get("composites", {})
    obfuscation = float(features.get("obfuscation_score", 0))
    n_indicators = len(features.get("network_indicators", []))
    n_perms = len(features.get("permissions", []))
    fmt = features.get("format", "")

    dangerous_perms = {
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.READ_CONTACTS",
    }
    perm_set = set(features.get("permissions", []))
    dangerous_hit = len(dangerous_perms & perm_set)

    score = 0.0
    score += min(dangerous_hit / 3.0, 1.0) * 0.35
    score += obfuscation * 0.25
    score += min(n_indicators / 5.0, 1.0) * 0.20
    if composites.get("full_device_control"):
        score += 0.20

    # Packed / dynamic-loader anomaly: APK with no declared permissions and
    # no network indicators is either empty (rare for real apps) or is hiding
    # its payload behind a loader — itself a strong malware signal.
    if fmt == "apk" and n_perms == 0 and n_indicators == 0:
        pkg = features.get("package_name", "")
        from analysis.static.extractor import _package_name_entropy
        pkg_entropy = _package_name_entropy(pkg)
        if pkg_entropy > 0.4:
            # Obfuscated package + zero manifest features = likely packed malware
            score = max(score, 0.75)
        else:
            # No permissions at all is still unusual — mild signal
            score = max(score, 0.35)

    return min(score, 1.0)


def _packed_apk_score(features: dict, composites: dict, obfuscation: float) -> float:
    """
    Detects packed / dynamic-loader APKs that hide malicious code at runtime.
    These evade all static behavioral checks, producing all-zero composites.
    Signals: no declared permissions + no network URLs + obfuscated package name.
    """
    if features.get("format") != "apk":
        return 0.0

    n_perms = len(features.get("permissions", []))
    n_net   = len(features.get("network_indicators", []))
    any_composite = any(
        bool(v) for v in composites.values() if isinstance(v, bool)
    ) or any(
        v > 0 for v in composites.values() if isinstance(v, (int, float))
    )

    # An APK with no permissions AND no composites is either empty or packed
    if n_perms > 5 or any_composite:
        return 0.0  # Normal app — static analysis found something

    # Check package name obfuscation (no external import needed — use bigram check inline)
    pkg = features.get("package_name", "") or ""
    pkg_entropy = _pkg_entropy_inline(pkg)

    if n_perms == 0 and n_net == 0 and pkg_entropy > 0.45:
        return 0.75  # Strong: zero manifest + obfuscated name = packed loader

    if n_perms == 0 and n_net == 0:
        return 0.45  # Moderate: zero manifest even with clean name is unusual

    if pkg_entropy > 0.60 and n_perms <= 2:
        return 0.50  # Highly obfuscated name with almost no permissions

    return 0.0


def _pkg_entropy_inline(package_name: str) -> float:
    """Bigram entropy check for package name without circular imports."""
    if not package_name:
        return 0.0
    common = {
        "th","he","in","er","an","re","on","en","at","ou","ed","nd","to","ha",
        "nt","is","or","it","be","st","ar","es","al","te","of","se","le","sa",
        "ro","si","ng","ba","di","li","co","me","de","ti","mo","ca","ma","ch",
        "la","ta","ra","pa","wa","mi","wi","sh","fi","hi","ri","lo","na","pr",
    }
    segments = [s for s in package_name.split(".")
                if s not in {"com","org","net","io","co","app","android"} and len(s) >= 5]
    if not segments:
        return 0.0
    scores = []
    for seg in segments:
        bigrams = {seg[i:i+2] for i in range(len(seg)-1)}
        ratio = len(bigrams & common) / max(len(bigrams), 1)
        scores.append(0.85 if ratio < 0.25 else 0.50 if ratio < 0.40 else 0.0)
    return sum(scores) / len(scores)


_SUSPICIOUS_TLDS = (".ru", ".cn", ".tk", ".top", ".xyz", ".pw", ".cc", ".su")
_KNOWN_SAFE_DOMAINS = (
    "google.com", "googleapis.com", "play.google.com", "gstatic.com",
    "android.com", "whatsapp.com", "whatsapp.net", "facebook.com",
    "fbcdn.net", "akamai.net", "cloudfront.net", "amazon.com",
    "amazonaws.com", "microsoft.com", "apple.com", "foursquare.com",
    "maps.google.com", "plus.google.com",
)


def _network_score(indicators: list) -> float:
    """
    Score based on suspicious network signals, not raw URL count.
    IPs, suspicious TLDs, non-HTTPS, and unknown domains score high.
    Known safe domains and standard schemas score near zero.
    """
    if not indicators:
        return 0.0

    score = 0.0
    for ind in indicators:
        itype = ind.get("type", "")
        val = ind.get("value", "")
        if itype == "ip":
            score += 0.8  # raw IP is always suspicious
        elif itype == "url":
            if any(val.lower().endswith(tld) or ("." + tld.lstrip(".") + "/") in val.lower()
                   for tld in _SUSPICIOUS_TLDS):
                score += 1.0
            elif any(domain in val.lower() for domain in _KNOWN_SAFE_DOMAINS):
                score += 0.05  # near-zero contribution from known-safe domains
            elif not val.startswith("https://"):
                score += 0.4  # plain HTTP to unknown domain is suspicious
            else:
                score += 0.15  # unknown HTTPS domain — mild signal

    return min(score / 10.0, 1.0)


def _severity_band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    else:
        return "LOW"


def _should_route_tier2(ml_score: float, obfuscation: float,
                        composites: dict, imperson_score: float,
                        risk_score: float) -> bool:
    high_severity = composites.get("full_device_control") or \
                    composites.get("rat_c2") or \
                    composites.get("process_injection") or \
                    composites.get("credential_theft")

    return (
        ml_score < 0.85 or
        obfuscation > 0.5 or
        imperson_score > 0 or
        bool(high_severity) or
        risk_score >= 61  # Any HIGH or CRITICAL goes to Tier 2
    )


def _is_whitelisted(cert_hash: str) -> bool:
    whitelist_path = Path(__file__).parent.parent.parent / "data" / "reference_db" / "bank_apps.json"
    if not whitelist_path.exists():
        return False
    import json
    with open(whitelist_path) as f:
        ref = json.load(f)
    known_hashes = {v.get("cert_hash_sha256", "") for v in ref.values()}
    known_hashes.discard("FETCH_FROM_PLAY_STORE")
    return cert_hash in known_hashes

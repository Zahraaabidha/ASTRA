"""
Static feature extractor for ASTRA.
Supports APK, Windows PE, Office macros, and scripts.
All formats produce the same unified behavioral schema.
"""

import hashlib
import json
import os
import re
from pathlib import Path


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(file_path: str) -> str:
    path = Path(file_path)
    ext = path.suffix.lower()

    with open(file_path, "rb") as f:
        magic = f.read(8)

    if magic[:4] == b"PK\x03\x04":
        return "apk"
    if magic[:2] == b"MZ":
        return "pe"
    if ext in {".js", ".ts"}:
        return "script_js"
    if ext in {".ps1"}:
        return "script_ps1"
    if ext in {".vbs", ".bat", ".cmd"}:
        return "script_vbs"
    if ext in {".doc", ".xls", ".ppt", ".docm", ".xlsm", ".docx", ".xlsx"}:
        return "macro"

    return "unknown"


# ---------------------------------------------------------------------------
# APK extraction
# ---------------------------------------------------------------------------

def extract_apk_features(file_path: str) -> dict:
    try:
        from androguard.misc import AnalyzeAPK
    except ImportError:
        return _error_schema("apk", "androguard not installed")

    try:
        apk, d, dx = AnalyzeAPK(file_path)
    except Exception as e:
        return _error_schema("apk", str(e))

    permissions = set(apk.get_permissions())
    certificate_hash = _get_apk_cert_hash(apk)
    method_index = {str(m.class_name) + "." + str(m.name) for m in dx.get_methods()}

    composites = {
        "otp_theft":           _check_otp_theft(permissions, dx),
        "fake_ui":             _check_fake_ui(permissions, dx),
        "full_device_control": _check_accessibility_abuse(permissions, dx),
        "data_exfiltration":   _check_exfiltration(permissions, dx),
        "rat_c2":              _check_rat_c2(permissions, dx),
        "anti_analysis":       _check_anti_analysis_apk(dx),
    }

    return {
        "format": "apk",
        "file_name": Path(file_path).name,
        "package_name": apk.get_package(),
        "app_name": apk.get_app_name(),
        "permissions": sorted(permissions),
        "certificate_hash": certificate_hash,
        "network_indicators": _extract_network_indicators_apk(dx),
        "composites": composites,
        "obfuscation_score": _obfuscation_score_apk(dx, apk.get_package() or ""),
        "method_index": list(method_index),
        "impersonation": _check_impersonation(apk, certificate_hash),
        "error": None,
    }


def _get_apk_cert_hash(apk) -> str:
    try:
        certs = apk.get_certificates()
        if certs:
            return hashlib.sha256(certs[0].dump()).hexdigest()
    except Exception:
        pass
    return ""


def _check_otp_theft(perms: set, dx) -> bool:
    has_sms = bool(perms & {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"})
    if not has_sms:
        return False
    methods = [str(m.class_name) + str(m.name) for m in dx.get_methods()]
    full = " ".join(methods)
    has_regex = "java/util/regex" in full
    has_network = any(p in full for p in ["HttpURLConnection", "OkHttp", "Retrofit", "URL;"])
    return has_regex and has_network


def _check_fake_ui(perms: set, dx) -> bool:
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms
    if not has_overlay:
        return False
    full = " ".join(str(m.class_name) for m in dx.get_methods())
    return "TYPE_APPLICATION_OVERLAY" in full or "TYPE_PHONE" in full or "WindowManager" in full


def _check_accessibility_abuse(perms: set, dx) -> bool:
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" not in perms:
        return False
    full = " ".join(str(m.name) for m in dx.get_methods())
    return "performAction" in full and "findAccessibilityNodeInfo" in full


def _check_exfiltration(perms: set, dx) -> bool:
    exfil_perms = {
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
    }
    has_exfil_perm = bool(perms & exfil_perms)
    full = " ".join(str(m.class_name) for m in dx.get_methods())
    has_network = any(p in full for p in ["HttpURLConnection", "OkHttp", "URL;"])
    return has_exfil_perm and has_network


def _check_rat_c2(perms: set, dx) -> bool:
    has_bg = "android.permission.RECEIVE_BOOT_COMPLETED" in perms
    full = " ".join(str(m.class_name) for m in dx.get_methods())
    has_socket = "java/net/Socket" in full or "ServerSocket" in full
    return has_bg and has_socket


def _check_anti_analysis_apk(dx) -> float:
    patterns = [
        "isEmulator", "getDeviceId", "BUILD/FINGERPRINT",
        "qemu", "goldfish", "getSensorList", "getSystemProperty",
    ]
    count = 0
    for m in dx.get_methods():
        src = str(m.class_name) + str(m.name)
        for p in patterns:
            if p.lower() in src.lower():
                count += 1
                break
    return round(min(count / 5.0, 1.0), 4)


def _obfuscation_score_apk(dx, package_name: str = "") -> float:
    methods = list(dx.get_methods())
    name_score = 0.0
    if methods:
        short_names = sum(1 for m in methods if len(str(m.name)) <= 2)
        name_score = short_names / len(methods)

    strings = list(dx.get_strings())
    encoded_score = 0.0
    if strings:
        encoded = sum(1 for s in strings if _looks_encoded(str(s)))
        encoded_score = encoded / len(strings)

    pkg_score = _package_name_entropy(package_name)

    return round(min((name_score + encoded_score + pkg_score) / 3, 1.0), 4)


def _package_name_entropy(package_name: str) -> float:
    """
    Randomly generated package names (like com.vfuaae.seduncible) score high.
    Uses character bigram frequency — English words have predictable bigrams;
    random strings do not. Also checks for suspiciously long non-word segments.
    """
    if not package_name:
        return 0.0
    segments = package_name.split(".")
    meaningful = [s for s in segments if s not in {"com", "org", "net", "io", "co", "app", "android"}]
    if not meaningful:
        return 0.0

    # Common English bigrams — real package names tend to use real words
    common_bigrams = {
        "th","he","in","er","an","re","on","en","at","ou","ed","nd","to","ha",
        "nt","is","or","it","be","st","ar","es","al","te","of","se","le","sa",
        "ro","si","ng","ba","di","li","co","me","de","ti","mo","ca","ma","ch",
        "la","ta","ra","pa","wa","mi","wi","sh","fi","hi","ri","lo","na","pr",
    }
    scores = []
    for seg in meaningful:
        seg = seg.lower()
        if len(seg) < 5:
            continue
        bigrams = {seg[i:i+2] for i in range(len(seg) - 1)}
        match_ratio = len(bigrams & common_bigrams) / max(len(bigrams), 1)
        # Real words typically match >40% of their bigrams against common English
        if match_ratio < 0.25:
            scores.append(0.85)
        elif match_ratio < 0.40:
            scores.append(0.50)
        else:
            scores.append(0.0)

    return round(sum(scores) / max(len(scores), 1), 4) if scores else 0.0


def _looks_encoded(s: str) -> bool:
    if len(s) < 8:
        return False
    b64 = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
    hex_re = re.compile(r'^[0-9a-fA-F]{16,}$')
    return bool(b64.match(s) or hex_re.match(s))


_BENIGN_URL_PREFIXES = (
    "http://schemas.android.com",
    "http://www.w3.org",
    "http://xml.org",
    "http://etherx.jabber.org",
    "http://jabber.org",
    "http://www.openmobilealliance.org",
    "https://schemas.android.com",
)

_BENIGN_IP_PREFIXES = ("127.", "10.", "192.168.", "0.0.0.0")


def _extract_network_indicators_apk(dx) -> list:
    indicators = []
    seen = set()
    url_re = re.compile(r'https?://[^\s"\'<>]{8,}')
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for s in dx.get_strings():
        val = str(s)
        for m in url_re.findall(val):
            if any(m.startswith(p) for p in _BENIGN_URL_PREFIXES):
                continue
            if m not in seen:
                seen.add(m)
                indicators.append({"type": "url", "value": m})
        for m in ip_re.findall(val):
            if any(m.startswith(p) for p in _BENIGN_IP_PREFIXES):
                continue
            if m not in seen:
                seen.add(m)
                indicators.append({"type": "ip", "value": m})
    return indicators[:50]


def _check_impersonation(apk, cert_hash: str) -> dict:
    ref_path = Path(__file__).parent.parent.parent / "data" / "reference_db" / "bank_apps.json"
    if not ref_path.exists():
        return {"flag": False, "matched_bank": None}

    with open(ref_path) as f:
        ref = json.load(f)

    package = apk.get_package() or ""
    app_name = _normalize_homographs((apk.get_app_name() or "")).lower()

    raw_app_name = (apk.get_app_name() or "").lower()
    homograph_used = app_name != raw_app_name

    for pkg, info in ref.items():
        bank_name = info.get("bank", "").lower()
        aliases = [bank_name] + [a.lower() for a in info.get("aliases", [])]

        matched = False
        for alias in aliases:
            if not alias:
                continue
            # Full alias match (standard)
            if alias in app_name:
                matched = True
                break
            # Short keyword match (≤6 chars) only when package is clearly wrong
            # prevents false positives while catching homograph + garbled-text attacks
            if len(alias) <= 6 and alias in app_name and package != pkg:
                matched = True
                break

        if matched:
            if package != pkg or cert_hash != info.get("cert_hash_sha256", ""):
                return {
                    "flag": True,
                    "matched_bank": info["bank"],
                    "expected_pkg": pkg,
                    "homograph_attack": homograph_used,
                }
    return {"flag": False, "matched_bank": None}


# Cyrillic and other Unicode lookalikes mapped to their Latin equivalents.
# Used to detect homograph impersonation attacks on bank app names.
_HOMOGRAPH_MAP = str.maketrans({
    'А':'A','В':'B','С':'C','Д':'D','Е':'E','Ғ':'F','Н':'H','І':'I',
    'Ј':'J','К':'K','М':'M','О':'O','Р':'P','Ѕ':'S','Т':'T','Х':'X',
    'Ү':'Y','а':'a','е':'e','і':'i','о':'o','р':'p','с':'c','ѕ':'s',
    'ԁ':'d','ԛ':'q','ԝ':'w','Ａ':'A','Ｂ':'B','Ｃ':'C','Ｄ':'D',
    'Ｅ':'E','Ｆ':'F','Ｇ':'G','Ｈ':'H','Ｉ':'I','Ｊ':'J','Ｋ':'K',
    'Ｌ':'L','Ｍ':'M','Ｎ':'N','Ｏ':'O','Ｐ':'P','Ｑ':'Q','Ｒ':'R',
    'Ｓ':'S','Ｔ':'T','Ｕ':'U','Ｖ':'V','Ｗ':'W','Ｘ':'X','Ｙ':'Y',
    'Ｚ':'Z','ａ':'a','ｂ':'b','ｃ':'c','ｄ':'d','ｅ':'e','ｆ':'f',
    'ｇ':'g','ｈ':'h','ｉ':'i','ｊ':'j','ｋ':'k','ｌ':'l','ｍ':'m',
    'ｎ':'n','ｏ':'o','ｐ':'p','ｑ':'q','ｒ':'r','ｓ':'s','ｔ':'t',
    'ｕ':'u','ｖ':'v','ｗ':'w','ｘ':'x','ｙ':'y','ｚ':'z',
})


def _normalize_homographs(text: str) -> str:
    """Replace Unicode lookalike characters with their ASCII equivalents."""
    return text.translate(_HOMOGRAPH_MAP)


# ---------------------------------------------------------------------------
# PE extraction
# ---------------------------------------------------------------------------

def extract_pe_features(file_path: str) -> dict:
    try:
        import pefile
    except ImportError:
        return _error_schema("pe", "pefile not installed — run: pip install pefile")

    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        return _error_schema("pe", str(e))

    imports = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="ignore")
            for imp in entry.imports:
                name = imp.name.decode(errors="ignore") if imp.name else f"ord_{imp.ordinal}"
                imports.append(f"{dll}::{name}")

    section_entropy = [
        {"name": s.Name.decode(errors="ignore").strip("\x00"), "entropy": round(s.get_entropy(), 4)}
        for s in pe.sections
    ]
    max_entropy = max((s["entropy"] for s in section_entropy), default=0)
    network_indicators = _extract_network_indicators_binary(file_path)

    composites = {
        "credential_theft":     _check_credential_theft_pe(imports),
        "process_injection":    _check_process_injection_pe(imports),
        "persistence":          _check_persistence_pe(imports),
        "network_exfiltration": bool(network_indicators),
        "packer_indicator":     max_entropy > 7.0,
        "anti_analysis":        _check_anti_analysis_pe(imports),
        "rat_c2":               _check_rat_c2_pe(imports),
    }

    return {
        "format": "pe",
        "file_name": Path(file_path).name,
        "imports": imports[:200],
        "section_entropy": section_entropy,
        "network_indicators": network_indicators,
        "composites": composites,
        "obfuscation_score": round(min(max_entropy / 8.0, 1.0), 4),
        "method_index": imports,
        "impersonation": {"flag": False, "matched_bank": None},
        "certificate_hash": _get_pe_signature_hash(pe),
        "error": None,
    }


def _check_credential_theft_pe(imports: list) -> bool:
    targets = {"OpenProcess", "ReadProcessMemory", "MiniDumpWriteDump", "LsaEnumerateLogonSessions"}
    import_names = {imp.split("::")[-1] for imp in imports}
    return bool(targets & import_names)


def _check_process_injection_pe(imports: list) -> bool:
    required = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}
    import_names = {imp.split("::")[-1] for imp in imports}
    return len(required & import_names) >= 2


def _check_persistence_pe(imports: list) -> bool:
    targets = {"RegSetValueExA", "RegSetValueExW", "RegOpenKeyExA", "CreateServiceA", "CreateServiceW"}
    import_names = {imp.split("::")[-1] for imp in imports}
    return bool(targets & import_names)


def _check_anti_analysis_pe(imports: list) -> float:
    targets = {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
               "GetTickCount", "QueryPerformanceCounter"}
    import_names = {imp.split("::")[-1] for imp in imports}
    matched = len(targets & import_names)
    return round(min(matched / 3.0, 1.0), 4)


def _check_rat_c2_pe(imports: list) -> bool:
    targets = {"WSAStartup", "connect", "send", "recv", "socket", "WinHttpOpen", "InternetOpenA"}
    import_names = {imp.split("::")[-1] for imp in imports}
    return len(targets & import_names) >= 2


def _get_pe_signature_hash(pe) -> str:
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            raw = pe.write()
            return hashlib.sha256(raw).hexdigest()
    except Exception:
        pass
    return ""


def _extract_network_indicators_binary(file_path: str) -> list:
    indicators = []
    url_re = re.compile(rb'https?://[^\x00\s"\'<>]{8,}')
    ip_re = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        for m in url_re.findall(data):
            indicators.append({"type": "url", "value": m.decode(errors="ignore")})
        for m in ip_re.findall(data):
            indicators.append({"type": "ip", "value": m.decode(errors="ignore")})
    except Exception:
        pass
    return indicators[:50]


# ---------------------------------------------------------------------------
# Macro extraction (Office files)
# ---------------------------------------------------------------------------

def extract_macro_features(file_path: str) -> dict:
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return _error_schema("macro", "oletools not installed — run: pip install oletools")

    try:
        vba = VBA_Parser(file_path)
    except Exception as e:
        return _error_schema("macro", str(e))

    if not vba.detect_vba_macros():
        return {
            "format": "macro",
            "file_name": Path(file_path).name,
            "has_macros": False,
            "composites": {k: False for k in ["execution", "download_execute", "anti_analysis"]},
            "obfuscation_score": 0.0,
            "network_indicators": [],
            "method_index": [],
            "impersonation": {"flag": False},
            "certificate_hash": "",
            "error": None,
        }

    all_code = ""
    for _, _, _, code in vba.extract_macros():
        all_code += (code or "")

    suspicious = [
        "Shell", "CreateObject", "WScript", "PowerShell",
        "DownloadFile", "URLDownloadToFile", "Environ",
        "AutoOpen", "Document_Open", "Chr(", "Asc(",
    ]
    keyword_hits = {k: k.lower() in all_code.lower() for k in suspicious}

    composites = {
        "execution":        keyword_hits.get("Shell") or keyword_hits.get("CreateObject"),
        "download_execute": keyword_hits.get("DownloadFile") or keyword_hits.get("URLDownloadToFile"),
        "auto_run":         keyword_hits.get("AutoOpen") or keyword_hits.get("Document_Open"),
        "anti_analysis":    0.0,
    }

    obfuscation = sum([
        keyword_hits.get("Chr(", False),
        keyword_hits.get("Asc(", False),
    ]) / 2.0

    return {
        "format": "macro",
        "file_name": Path(file_path).name,
        "has_macros": True,
        "keyword_hits": keyword_hits,
        "composites": composites,
        "obfuscation_score": round(obfuscation, 4),
        "network_indicators": _extract_network_indicators_text(all_code),
        "method_index": list(keyword_hits.keys()),
        "impersonation": {"flag": False},
        "certificate_hash": "",
        "error": None,
    }


# ---------------------------------------------------------------------------
# Script extraction
# ---------------------------------------------------------------------------

def extract_script_features(file_path: str, script_type: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()
    except Exception as e:
        return _error_schema(script_type, str(e))

    keyword_map = {
        "script_js":  ["eval(", "Function(", "atob(", "unescape(", "XMLHttpRequest", "fetch(", "ActiveXObject"],
        "script_ps1": ["Invoke-Expression", "IEX", "DownloadString", "DownloadFile",
                       "Start-Process", "New-Object", "-EncodedCommand"],
        "script_vbs": ["Shell", "CreateObject", "WScript.Shell", "Execute", "DownloadFile"],
    }
    keywords = keyword_map.get(script_type, [])
    hits = {k: k.lower() in code.lower() for k in keywords}

    obfuscation = _script_obfuscation_score(code)
    network_indicators = _extract_network_indicators_text(code)

    composites = {
        "execution":         any(hits.values()),
        "download_execute":  any("download" in k.lower() and v for k, v in hits.items()),
        "obfuscation_heavy": obfuscation > 0.3,
        "anti_analysis":     0.0,
    }

    return {
        "format": script_type,
        "file_name": Path(file_path).name,
        "keyword_hits": hits,
        "composites": composites,
        "obfuscation_score": round(obfuscation, 4),
        "network_indicators": network_indicators,
        "method_index": list(hits.keys()),
        "impersonation": {"flag": False},
        "certificate_hash": "",
        "error": None,
    }


def _script_obfuscation_score(code: str) -> float:
    total = max(len(code), 1)
    encoded = len(re.findall(r'\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}', code))
    return min(encoded / (total / 4), 1.0)


def _extract_network_indicators_text(code: str) -> list:
    indicators = []
    for m in re.findall(r'https?://[^\s"\'<>]{8,}', code):
        indicators.append({"type": "url", "value": m})
    for m in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', code):
        indicators.append({"type": "ip", "value": m})
    return indicators[:50]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def extract_features(file_path: str) -> dict:
    fmt = detect_format(file_path)
    if fmt == "apk":
        return extract_apk_features(file_path)
    elif fmt == "pe":
        return extract_pe_features(file_path)
    elif fmt == "macro":
        return extract_macro_features(file_path)
    elif fmt.startswith("script_"):
        return extract_script_features(file_path, fmt)
    else:
        return _error_schema("unknown", f"Unsupported format: {fmt}")


def _error_schema(fmt: str, error: str) -> dict:
    return {
        "format": fmt,
        "file_name": "",
        "composites": {},
        "obfuscation_score": 0.0,
        "network_indicators": [],
        "method_index": [],
        "impersonation": {"flag": False},
        "certificate_hash": "",
        "error": error,
    }

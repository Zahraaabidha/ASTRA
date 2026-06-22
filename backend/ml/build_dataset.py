"""
Build a training CSV from labeled APK folders.

Usage:
    python backend/ml/build_dataset.py
        --malware  path/to/malware_apks/
        --benign   path/to/benign_apks/
        --out      data/models/training_data.csv

The script runs our static extractor on every APK and writes one row per APK
with our exact feature schema + a Label column (Malicious / Benign).
"""

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from analysis.static.extractor import extract_features


FEATURE_KEYS = [
    # Behavioral composites (binary / float)
    "otp_theft", "fake_ui", "full_device_control",
    "data_exfiltration", "rat_c2", "anti_analysis",
    # Numeric scores
    "obfuscation_score",
    # Counts
    "num_permissions", "num_dangerous_perms", "num_network_indicators",
    # Impersonation
    "impersonation_flag",
]

DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.WRITE_SETTINGS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.USE_CREDENTIALS",
}


def featurize(features: dict) -> dict:
    composites = features.get("composites", {})
    perms = set(features.get("permissions", []))
    network = features.get("network_indicators", [])

    return {
        "otp_theft":            int(bool(composites.get("otp_theft", False))),
        "fake_ui":              int(bool(composites.get("fake_ui", False))),
        "full_device_control":  int(bool(composites.get("full_device_control", False))),
        "data_exfiltration":    int(bool(composites.get("data_exfiltration", False))),
        "rat_c2":               int(bool(composites.get("rat_c2", False))),
        "anti_analysis":        float(composites.get("anti_analysis", 0)),
        "obfuscation_score":    float(features.get("obfuscation_score", 0)),
        "num_permissions":      len(perms),
        "num_dangerous_perms":  len(perms & DANGEROUS_PERMS),
        "num_network_indicators": len(network),
        "impersonation_flag":   int(bool(features.get("impersonation", {}).get("flag", False))),
    }


def process_folder(folder: Path, label: str) -> list[dict]:
    rows = []
    apks = list(folder.glob("*.apk")) + list(folder.glob("*.dex"))
    print(f"\n{label}: found {len(apks)} APKs in {folder}")
    for apk in apks:
        print(f"  Extracting {apk.name} ...", end=" ", flush=True)
        try:
            features = extract_features(str(apk))
            row = featurize(features)
            row["Label"] = label
            row["file"] = apk.name
            rows.append(row)
            print("ok")
        except Exception as e:
            print(f"FAILED: {e}")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--malware", required=True, help="Folder of malware APKs")
    parser.add_argument("--benign",  required=True, help="Folder of benign APKs")
    parser.add_argument("--out", default=str(ROOT / "data" / "models" / "training_data.csv"))
    args = parser.parse_args()

    malware_rows = process_folder(Path(args.malware), "Malicious")
    benign_rows  = process_folder(Path(args.benign),  "Benign")
    all_rows = malware_rows + benign_rows

    if not all_rows:
        print("No APKs processed. Check your folder paths.")
        sys.exit(1)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = ["file"] + FEATURE_KEYS + ["Label"]
    with open(out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\nDataset written: {out}")
    print(f"  {len(malware_rows)} malware  +  {len(benign_rows)} benign  =  {len(all_rows)} total")
    print(f"\nNext step:")
    print(f"  python backend\\ml\\train.py --csv {out} --out data\\models\\classifier.pkl")


if __name__ == "__main__":
    main()

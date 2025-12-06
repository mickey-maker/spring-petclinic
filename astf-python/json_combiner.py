import json
import os

DATA_DIR = "astf-python/data"
OUTPUT_FILE = "astf-python/combined_astf.json"

FILES = {
    "sast": "sast.json",
    "dast": "dast.json",
    "sca": "sca.json"
}

def load_json_safe(path):
    if not os.path.exists(path):
        print(f"[WARN] Missing file: {path}")
        return []

    if os.stat(path).st_size == 0:
        print(f"[WARN] Empty file: {path}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON {path}: {e}")
        return []

combined = []

print("[ASTF] Loading SAST, DAST & SCA JSON files...")

# ✅ SAST — SonarCloud issues (VULN + BUG + CODE SMELL)
sast_data = load_json_safe(os.path.join(DATA_DIR, FILES["sast"]))
if "issues" in sast_data:
    for issue in sast_data["issues"]:
        combined.append({
            "tool": "SAST",
            "type": issue.get("type", "UNKNOWN"),          # ✅ BUG / VULNERABILITY / CODE_SMELL
            "severity": issue.get("severity", "INFO"),
            "message": issue.get("message", ""),
            "file": issue.get("component", ""),
            "rule": issue.get("rule", "")
        })

# ✅ DAST — ZAP
dast_data = load_json_safe(os.path.join(DATA_DIR, FILES["dast"]))
if "site" in dast_data:
    for site in dast_data["site"]:
        for alert in site.get("alerts", []):
            combined.append({
                "tool": "DAST",
                "type": "VULNERABILITY",
                "severity": alert.get("riskdesc", ""),
                "message": alert.get("alert", ""),
                "file": alert.get("uri", ""),
                "rule": alert.get("pluginid", "")
            })

# ✅ SCA — Snyk
sca_data = load_json_safe(os.path.join(DATA_DIR, FILES["sca"]))
if "vulnerabilities" in sca_data:
    for vuln in sca_data["vulnerabilities"]:
        combined.append({
            "tool": "SCA",
            "type": "VULNERABILITY",
            "severity": vuln.get("severity", ""),
            "message": vuln.get("title", ""),
            "file": vuln.get("packageName", ""),
            "rule": vuln.get("id", "")
        })

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(combined, f, indent=2)

print(f"[ASTF] ✅ Combined ASTF file created: {OUTPUT_FILE}")
print(f"[ASTF] ✅ Total merged alerts: {len(combined)}")

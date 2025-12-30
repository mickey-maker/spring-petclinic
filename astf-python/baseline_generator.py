"""
BASELINE ALERT GENERATOR

Purpose:
- Generate baseline security alerts from raw SAST, DAST, and SCA outputs
- No deduplication
- No suppression
- No prioritisation or scoring
- Used for Chapter 5 baseline comparison against ASTF

Output:
- astf-python/output/baseline_alerts.csv
"""

import os
import json
import csv

# ===============================
# CONFIGURATION
# ===============================
DATA_DIR = "astf-python/data"
OUTPUT_DIR = "astf-python/output"
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "baseline_alerts.csv")

FILES = {
    "sast": "sast.json",
    "dast": "dast.json",
    "sca": "sca.json",
}

# ===============================
# HELPERS
# ===============================
def load_json_safe(path: str):
    if not os.path.exists(path):
        print(f"[BASELINE] ⚠ Missing file: {path}")
        return {}
    if os.stat(path).st_size == 0:
        print(f"[BASELINE] ⚠ Empty file: {path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[BASELINE] ❌ Failed to parse JSON {path}: {e}")
        return {}

def to_int_or_none(x):
    if x in (None, "", "None"):
        return None
    try:
        return int(str(x).strip())
    except Exception:
        return None

def normalize_sonar_severity(sev: str) -> str:
    mapping = {
        "BLOCKER": "CRITICAL",
        "CRITICAL": "HIGH",
        "MAJOR": "MEDIUM",
        "MINOR": "LOW",
        "INFO": "INFO"
    }
    return mapping.get(str(sev or "").upper().strip(), "INFO")

def normalize_zap_riskdesc(riskdesc: str) -> str:
    text = str(riskdesc or "").upper().strip()
    if not text:
        return "INFO"
    first = text.split()[0]
    if first == "INFORMATIONAL":
        return "INFO"
    if first in {"HIGH", "MEDIUM", "LOW"}:
        return first
    return "INFO"

def normalize_snyk_severity(sev: str) -> str:
    s = str(sev or "").upper().strip()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return s
    return "INFO"

# ===============================
# MAIN
# ===============================
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    rows = []
    print("[BASELINE] Generating baseline alerts (raw tool outputs only)")

    # =========================
    # SAST — SonarCloud
    # =========================
    sast_data = load_json_safe(os.path.join(DATA_DIR, FILES["sast"]))
    if isinstance(sast_data, dict) and "issues" in sast_data:
        for issue in sast_data.get("issues", []):
            file_path = str(issue.get("component", "")).strip()
            line_no = to_int_or_none(issue.get("line", None))
            location = f"{file_path}:{line_no}" if (file_path and line_no is not None) else file_path

            rows.append({
                "tool": "SAST",
                "alert_id": str(issue.get("key", "")).strip(),
                "type": str(issue.get("type", "UNKNOWN")).upper().strip(),
                "severity": normalize_sonar_severity(issue.get("severity", "")),
                "message": issue.get("message", ""),
                "rule": str(issue.get("rule", "")).strip(),
                "location": location,
                "file_or_endpoint": file_path,
                "line": line_no
            })

    # =========================
    # DAST — OWASP ZAP
    # =========================
    dast_data = load_json_safe(os.path.join(DATA_DIR, FILES["dast"]))
    if isinstance(dast_data, dict) and "site" in dast_data:
        for site in dast_data.get("site", []):
            for alert in site.get("alerts", []):
                plugin_id = str(alert.get("pluginid", "")).strip()
                msg = alert.get("alert", "")
                sev = normalize_zap_riskdesc(alert.get("riskdesc", ""))

                instances = alert.get("instances", [])
                if isinstance(instances, list) and instances:
                    for inst in instances:
                        uri = str(inst.get("uri", "")).strip() or str(alert.get("uri", "")).strip()
                        rows.append({
                            "tool": "DAST",
                            "alert_id": plugin_id,
                            "type": "VULNERABILITY",
                            "severity": sev,
                            "message": msg,
                            "rule": plugin_id,
                            "location": uri,
                            "file_or_endpoint": uri,
                            "line": None
                        })
                else:
                    uri = str(alert.get("uri", "")).strip()
                    rows.append({
                        "tool": "DAST",
                        "alert_id": plugin_id,
                        "type": "VULNERABILITY",
                        "severity": sev,
                        "message": msg,
                        "rule": plugin_id,
                        "location": uri,
                        "file_or_endpoint": uri,
                        "line": None
                    })

    # =========================
    # SCA — Snyk / Dependabot
    # =========================
    sca_data = load_json_safe(os.path.join(DATA_DIR, FILES["sca"]))
    if isinstance(sca_data, dict) and "vulnerabilities" in sca_data:
        for vuln in sca_data.get("vulnerabilities", []):
            pkg = str(vuln.get("packageName", "")).strip()
            module = str(vuln.get("moduleName", "")).strip()
            location = module if module else pkg

            rows.append({
                "tool": "SCA",
                "alert_id": str(vuln.get("id", "")).strip(),
                "type": "VULNERABILITY",
                "severity": normalize_snyk_severity(vuln.get("severity", "")),
                "message": vuln.get("title", ""),
                "rule": str(vuln.get("id", "")).strip(),
                "location": location,
                "file_or_endpoint": location,
                "line": None
            })

    # =========================
    # WRITE CSV (ALWAYS)
    # =========================
    headers = [
        "tool", "alert_id", "type", "severity",
        "message", "rule", "location",
        "file_or_endpoint", "line"
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[BASELINE] ✅ baseline_alerts.csv written: {OUTPUT_CSV}")
    print(f"[BASELINE] ✅ Total baseline alerts: {len(rows)}")

if __name__ == "__main__":
    main()

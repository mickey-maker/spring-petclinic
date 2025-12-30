import json
import csv
import os
from datetime import datetime

# ===============================
# CONFIG
# ===============================
DATA_DIR = "data"
OUTPUT_FILE = "baseline_alerts.csv"

SONAR_FILE = os.path.join(DATA_DIR, "sonar.json")
ZAP_FILE = os.path.join(DATA_DIR, "zap.json")
SCA_FILE = os.path.join(DATA_DIR, "sca.json")

# ===============================
# HELPER
# ===============================
def now_ts():
    return datetime.utcnow().isoformat()

baseline_rows = []

# ===============================
# SAST - SONARQUBE
# ===============================
if os.path.exists(SONAR_FILE):
    with open(SONAR_FILE, "r", encoding="utf-8") as f:
        sonar = json.load(f)

    issues = sonar.get("issues", [])
    for issue in issues:
        baseline_rows.append({
            "tool": "SAST",
            "alert_id": issue.get("key", ""),
            "severity_tool": issue.get("severity", ""),
            "type": issue.get("type", ""),
            "file_or_endpoint": issue.get("component", ""),
            "message": issue.get("message", ""),
            "rule": issue.get("rule", ""),
            "timestamp": now_ts()
        })

# ===============================
# DAST - OWASP ZAP
# ===============================
if os.path.exists(ZAP_FILE):
    with open(ZAP_FILE, "r", encoding="utf-8") as f:
        zap = json.load(f)

    alerts = zap.get("site", [{}])[0].get("alerts", [])
    for alert in alerts:
        baseline_rows.append({
            "tool": "DAST",
            "alert_id": alert.get("alertRef", ""),
            "severity_tool": alert.get("riskdesc", ""),
            "type": "VULNERABILITY",
            "file_or_endpoint": alert.get("url", ""),
            "message": alert.get("desc", ""),
            "rule": alert.get("pluginid", ""),
            "timestamp": now_ts()
        })

# ===============================
# SCA - SNYK / DEPENDABOT
# ===============================
if os.path.exists(SCA_FILE):
    with open(SCA_FILE, "r", encoding="utf-8") as f:
        sca = json.load(f)

    vulns = sca.get("vulnerabilities", [])
    for v in vulns:
        baseline_rows.append({
            "tool": "SCA",
            "alert_id": v.get("id", ""),
            "severity_tool": v.get("severity", ""),
            "type": "DEPENDENCY",
            "file_or_endpoint": v.get("packageName", ""),
            "message": v.get("title", ""),
            "rule": v.get("id", ""),
            "timestamp": now_ts()
        })

# ===============================
# WRITE CSV
# ===============================
if baseline_rows:
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=baseline_rows[0].keys()
        )
        writer.writeheader()
        writer.writerows(baseline_rows)

    print(f"[BASELINE] ✅ baseline_alerts.csv generated ({len(baseline_rows)} alerts)")
else:
    print("[BASELINE] ⚠ No alerts found – CSV not generated")

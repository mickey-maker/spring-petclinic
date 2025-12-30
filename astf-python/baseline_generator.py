"""
BASELINE ALERT GENERATOR (SEPARATE SHEETS ONLY)

Purpose:
- Generate baseline security alerts
- NO deduplication
- NO suppression
- NO aggregation / combination
- Each tool is stored in its own sheet

Outputs:
- baseline_master.xlsx
"""

import os
import json
import pandas as pd

# ===============================
# CONFIGURATION
# ===============================
DATA_DIR = "astf-python/data"
OUTPUT_DIR = "astf-python/output"

OUTPUT_XLSX = os.path.join(OUTPUT_DIR, "baseline_master.xlsx")

FILES = {
    "sast": "sast.json",
    "dast": "dast.json",
    "sca": "sca.json",
}

# ===============================
# HELPERS
# ===============================
def load_json_safe(path):
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

def normalize_sonar_severity(sev):
    mapping = {
        "BLOCKER": "CRITICAL",
        "CRITICAL": "HIGH",
        "MAJOR": "MEDIUM",
        "MINOR": "LOW",
        "INFO": "INFO"
    }
    return mapping.get(str(sev or "").upper(), "INFO")

def normalize_zap_severity(riskdesc):
    text = str(riskdesc or "").upper()
    if not text:
        return "INFO"
    first = text.split()[0]
    if first == "INFORMATIONAL":
        return "INFO"
    if first in {"HIGH", "MEDIUM", "LOW"}:
        return first
    return "INFO"

def normalize_snyk_severity(sev):
    s = str(sev or "").upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return s
    return "INFO"

# ===============================
# MAIN
# ===============================
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    baseline_sast = []
    baseline_dast = []
    baseline_sca = []

    print("[BASELINE] Generating baseline alerts (NO aggregation)")

    # =========================
    # SAST — SonarCloud
    # =========================
    sast_data = load_json_safe(os.path.join(DATA_DIR, FILES["sast"]))
    if isinstance(sast_data, dict) and "issues" in sast_data:
        for issue in sast_data["issues"]:
            baseline_sast.append({
                "tool": "SAST",
                "alert_id": issue.get("key"),
                "type": str(issue.get("type", "")).upper(),
                "severity": normalize_sonar_severity(issue.get("severity")),
                "message": issue.get("message"),
                "rule": issue.get("rule"),
                "file": issue.get("component"),
                "line": issue.get("line")
            })

    # =========================
    # DAST — OWASP ZAP
    # =========================
    dast_data = load_json_safe(os.path.join(DATA_DIR, FILES["dast"]))
    if isinstance(dast_data, dict) and "site" in dast_data:
        for site in dast_data["site"]:
            for alert in site.get("alerts", []):
                sev = normalize_zap_severity(alert.get("riskdesc"))
                plugin = alert.get("pluginid")
                msg = alert.get("alert")

                instances = alert.get("instances", [])
                if instances:
                    for inst in instances:
                        baseline_dast.append({
                            "tool": "DAST",
                            "alert_id": plugin,
                            "type": "VULNERABILITY",
                            "severity": sev,
                            "message": msg,
                            "url": inst.get("uri"),
                            "param": inst.get("param")
                        })
                else:
                    baseline_dast.append({
                        "tool": "DAST",
                        "alert_id": plugin,
                        "type": "VULNERABILITY",
                        "severity": sev,
                        "message": msg,
                        "url": alert.get("uri"),
                        "param": None
                    })

    # =========================
    # SCA — Snyk / Dependabot
    # =========================
    sca_data = load_json_safe(os.path.join(DATA_DIR, FILES["sca"]))
    if isinstance(sca_data, dict) and "vulnerabilities" in sca_data:
        for vuln in sca_data["vulnerabilities"]:
            baseline_sca.append({
                "tool": "SCA",
                "alert_id": vuln.get("id"),
                "type": "VULNERABILITY",
                "severity": normalize_snyk_severity(vuln.get("severity")),
                "message": vuln.get("title"),
                "package": vuln.get("packageName"),
                "version": vuln.get("version")
            })

    # =========================
    # SAVE EXCEL (SEPARATE SHEETS)
    # =========================
    with pd.ExcelWriter(OUTPUT_XLSX, engine="openpyxl") as writer:
        pd.DataFrame(baseline_sast).to_excel(writer, sheet_name="BASELINE_SAST", index=False)
        pd.DataFrame(baseline_dast).to_excel(writer, sheet_name="BASELINE_DAST", index=False)
        pd.DataFrame(baseline_sca).to_excel(writer, sheet_name="BASELINE_SCA", index=False)

    print("[BASELINE] ✅ baseline_master.xlsx created")
    print(f"[BASELINE] SAST alerts: {len(baseline_sast)}")
    print(f"[BASELINE] DAST alerts: {len(baseline_dast)}")
    print(f"[BASELINE] SCA alerts: {len(baseline_sca)}")

if __name__ == "__main__":
    main()

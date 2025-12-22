import json
import os

DATA_DIR = "astf-python/data"
OUTPUT_FILE = "astf-python/combined_astf.json"

FILES = {
    "sast": "sast.json",
    "dast": "dast.json",
    "sca": "sca.json"
}


def normalize_sonar_severity(sev: str) -> str:
    s = str(sev or "").strip().upper()
    mapping = {
        "BLOCKER": "CRITICAL",
        "CRITICAL": "HIGH",
        "MAJOR": "MEDIUM",
        "MINOR": "LOW",
        "INFO": "INFO"
    }
    return mapping.get(s, "INFO")


def normalize_zap_riskdesc(riskdesc: str) -> str:
    text = str(riskdesc or "").strip().upper()
    if not text:
        return "INFO"
    first = text.split()[0]
    if first == "INFORMATIONAL":
        return "INFO"
    if first in {"HIGH", "MEDIUM", "LOW"}:
        return first
    return "INFO"


def normalize_snyk_severity(sev: str) -> str:
    s = str(sev or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return s
    return "INFO"


def load_json_safe(path: str):
    if not os.path.exists(path):
        print(f"[WARN] Missing file: {path}")
        return {}
    if os.stat(path).st_size == 0:
        print(f"[WARN] Empty file: {path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON {path}: {e}")
        return {}


def _safe_int(value, default=None):
    try:
        if value is None or value == "":
            return default
        return int(value)
    except Exception:
        return default


def main():
    combined = []
    print("[ASTF] Loading SAST, DAST & SCA JSON files...")

    # =========================
    # SAST — SonarCloud
    # =========================
    sast_data = load_json_safe(os.path.join(DATA_DIR, FILES["sast"]))
    if isinstance(sast_data, dict) and "issues" in sast_data:
        for issue in sast_data.get("issues", []):
            # Sonar issues often include "line"
            line = _safe_int(issue.get("line", None), default=None)

            combined.append({
                "tool": "SAST",
                "type": issue.get("type", "UNKNOWN"),
                "severity": normalize_sonar_severity(issue.get("severity", "INFO")),
                "message": issue.get("message", ""),
                "file": issue.get("component", ""),
                "rule": issue.get("rule", ""),
                "line": line
            })

    # =========================
    # DAST — ZAP
    # =========================
    dast_data = load_json_safe(os.path.join(DATA_DIR, FILES["dast"]))
    if isinstance(dast_data, dict) and "site" in dast_data:
        for site in dast_data.get("site", []):
            for alert in site.get("alerts", []):
                # ZAP is endpoint-based; no code line. Keep None.
                combined.append({
                    "tool": "DAST",
                    "type": "VULNERABILITY",
                    "severity": normalize_zap_riskdesc(alert.get("riskdesc", "")),
                    "message": alert.get("alert", ""),
                    "file": alert.get("uri", ""),
                    "rule": str(alert.get("pluginid", "")),
                    "line": None
                })

    # =========================
    # SCA — Snyk
    # =========================
    sca_data = load_json_safe(os.path.join(DATA_DIR, FILES["sca"]))
    if isinstance(sca_data, dict) and "vulnerabilities" in sca_data:
        for vuln in sca_data.get("vulnerabilities", []):
            # Snyk is dependency-based; no code line. Keep None.
            combined.append({
                "tool": "SCA",
                "type": "VULNERABILITY",
                "severity": normalize_snyk_severity(vuln.get("severity", "")),
                "message": vuln.get("title", ""),
                "file": vuln.get("packageName", ""),
                "rule": vuln.get("id", ""),
                "line": None
            })

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    print(f"[ASTF] ✅ Combined ASTF file created: {OUTPUT_FILE}")
    print(f"[ASTF] ✅ Total merged alerts: {len(combined)}")


if __name__ == "__main__":
    main()

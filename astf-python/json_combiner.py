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


def to_int_or_none(val):
    try:
        if val is None:
            return None
        s = str(val).strip()
        if s == "" or s.lower() == "none":
            return None
        return int(float(s))
    except Exception:
        return None


def main():
    combined = []
    print("[ASTF] Loading SAST, DAST & SCA JSON files...")

    # =========================
    # SAST — SonarCloud
    # =========================
    sast_data = load_json_safe(os.path.join(DATA_DIR, FILES["sast"]))
    if isinstance(sast_data, dict) and "issues" in sast_data:
        for issue in sast_data.get("issues", []):
            component = str(issue.get("component", "")).strip()
            # Sonar often stores "projectKey:path/to/file"
            # Keep as-is, or optionally split after ":" if you want only file path.
            file_path = component

            line_no = to_int_or_none(issue.get("line", None))
            location = f"{file_path}:{line_no}" if (file_path and line_no is not None) else file_path

            combined.append({
                "tool": "SAST",
                "type": issue.get("type", "UNKNOWN"),
                "severity": normalize_sonar_severity(issue.get("severity", "INFO")),
                "message": issue.get("message", ""),
                "file": file_path,
                "rule": issue.get("rule", ""),
                "line": line_no,         # ✅ int or None
                "location": location     # ✅ always string
            })

    # =========================
    # DAST — ZAP
    # =========================
    dast_data = load_json_safe(os.path.join(DATA_DIR, FILES["dast"]))
    if isinstance(dast_data, dict) and "site" in dast_data:
        for site in dast_data.get("site", []):
            for alert in site.get("alerts", []):
                # Depending on export version, uri may be inside instances.
                uri = str(alert.get("uri", "")).strip()

                if not uri:
                    instances = alert.get("instances", []) or []
                    if instances and isinstance(instances, list):
                        uri = str(instances[0].get("uri", "")).strip()

                pluginid = str(alert.get("pluginid", "")).strip()
                location = uri ( ) if uri else f"PLUGIN:{pluginid}"

                combined.append({
                    "tool": "DAST",
                    "type": "VULNERABILITY",
                    "severity": normalize_zap_riskdesc(alert.get("riskdesc", "")),
                    "message": alert.get("alert", ""),
                    "file": uri,            # endpoint stored here
                    "rule": pluginid,
                    "line": None,           # ✅ no line for DAST
                    "location": uri if uri else f"PLUGIN:{pluginid}"
                })

    # =========================
    # SCA — Snyk
    # =========================
    sca_data = load_json_safe(os.path.join(DATA_DIR, FILES["sca"]))
    if isinstance(sca_data, dict) and "vulnerabilities" in sca_data:
        for vuln in sca_data.get("vulnerabilities", []):
            pkg = str(vuln.get("packageName", "")).strip()
            module = str(vuln.get("moduleName", "")).strip()  # often includes version
            cve_id = str(vuln.get("id", "")).strip()
            title = str(vuln.get("title", "")).strip()

            # Better “location” for SCA is moduleName (usually pkg@version) when available
            location = module if module else pkg

            combined.append({
                "tool": "SCA",
                "type": "VULNERABILITY",
                "severity": normalize_snyk_severity(vuln.get("severity", "")),
                "message": title,
                "file": pkg,             # package name
                "rule": cve_id,
                "line": None,            # ✅ no line for SCA
                "location": location
            })

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    print(f"[ASTF] ✅ Combined ASTF file created: {OUTPUT_FILE}")
    print(f"[ASTF] ✅ Total merged alerts: {len(combined)}")


if __name__ == "__main__":
    main()

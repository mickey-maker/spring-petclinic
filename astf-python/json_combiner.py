import json
from pathlib import Path

# Base folders
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

OUTPUT_FILE = BASE_DIR / "combined_astf.json"


def load_json(path: Path):
    """
    Generic JSON loader with UTF-8 + UTF-16 fallback.
    """
    if not path.exists():
        print(f"[WARN] File not found: {path}")
        return {}

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        try:
            return json.loads(path.read_text(encoding="utf-16"))
        except Exception as ex:
            print(f"[ERROR] Failed to parse JSON {path}: {ex}")
            return {}
    except Exception as ex:
        print(f"[ERROR] Failed to parse JSON {path}: {ex}")
        return {}


def extract_dast_alerts(dast_raw):
    """
    Support both:
    - {"alerts": [...]}
    - {"site": [ { "alerts": [...] }, ... ]}
    """
    alerts = []

    if not isinstance(dast_raw, dict):
        return alerts

    # Simple format: root.alerts
    if "alerts" in dast_raw and isinstance(dast_raw["alerts"], list):
        return dast_raw["alerts"]

    # ZAP full report format: root.site[*].alerts[*]
    if "site" in dast_raw:
        sites = dast_raw["site"]
        if isinstance(sites, dict):
            sites = [sites]
        if isinstance(sites, list):
            for site in sites:
                if not isinstance(site, dict):
                    continue
                for alert in site.get("alerts", []):
                    alerts.append(alert)

    return alerts


def extract_sca_vulns(sca_raw):
    """
    Support:
    - {"vulnerabilities": [ ... ]}
    - [ ... ] directly
    """
    if isinstance(sca_raw, dict):
        return sca_raw.get("vulnerabilities", [])
    if isinstance(sca_raw, list):
        return sca_raw
    return []


def main():
    print("[ASTF] Loading SAST, DAST & SCA JSON files...")

    sast = load_json(DATA_DIR / "sast.json")
    dast_raw = load_json(DATA_DIR / "dast.json")
    sca_raw = load_json(DATA_DIR / "sca.json")

    combined = []

    # ---------- SAST (SonarQube) ----------
    for issue in sast.get("issues", []):
        combined.append({
            "source": "SAST",
            "rule_id": issue.get("rule"),
            "severity": (issue.get("severity") or "LOW").upper(),
            "location": f"{issue.get('component')}:{issue.get('line', 0)}",
            "description": issue.get("message"),
        })

    # ---------- DAST (OWASP ZAP) ----------
    dast_alerts = extract_dast_alerts(dast_raw)
    for alert in dast_alerts:
        # ZAP sometimes has `risk` or `riskdesc` like "Low (Medium confidence)"
        risk = alert.get("risk") or alert.get("riskdesc", "LOW").split(" ")[0]
        location = alert.get("url") or alert.get("uri")
        desc = alert.get("description") or alert.get("desc") or alert.get("otherinfo")

        combined.append({
            "source": "DAST",
            "rule_id": alert.get("alert") or alert.get("name"),
            "severity": (risk or "LOW").upper(),
            "location": location,
            "description": desc,
        })

    # ---------- SCA (Snyk) ----------
    sca_vulns = extract_sca_vulns(sca_raw)
    for v in sca_vulns:
        severity = v.get("severity") or v.get("severityWithCritical") or "LOW"
        from_chain = v.get("from", [])
        location = " > ".join(from_chain) if from_chain else v.get("moduleName") or v.get("name")

        combined.append({
            "source": "SCA",
            "rule_id": v.get("id"),
            "severity": (severity or "LOW").upper(),
            "location": location,
            "description": v.get("title"),
        })

    # ---------- Write output ----------
    OUTPUT_FILE.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    print(f"[ASTF] ✅ Combined ASTF file created: {OUTPUT_FILE}")
    print(f"[ASTF] ✅ Total merged alerts: {len(combined)}")


if __name__ == "__main__":
    main()

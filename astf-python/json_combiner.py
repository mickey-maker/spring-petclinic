import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_FILE = BASE_DIR / "combined_astf.json"


def safe_load_json(path: Path):
    if not path.exists():
        print(f"[WARN] Missing file: {path.name}")
        return {}

    try:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            print(f"[WARN] Empty file: {path.name}")
            return {}
        return json.loads(text)
    except Exception as e:
        print(f"[ERROR] Failed to parse JSON {path.name}: {e}")
        return {}


def extract_dast_alerts(dast_raw):
    alerts = []

    if isinstance(dast_raw, dict):
        if "alerts" in dast_raw:
            return dast_raw["alerts"]

        if "site" in dast_raw:
            sites = dast_raw.get("site", [])
            if isinstance(sites, dict):
                sites = [sites]
            for site in sites:
                alerts.extend(site.get("alerts", []))

    return alerts


def extract_sca(sca_raw):
    if isinstance(sca_raw, dict):
        return sca_raw.get("vulnerabilities", [])
    if isinstance(sca_raw, list):
        return sca_raw
    return []


def main():
    print("[ASTF] Loading SAST, DAST & SCA JSON files...")

    sast = safe_load_json(DATA_DIR / "sast.json")
    dast = safe_load_json(DATA_DIR / "dast.json")
    sca = safe_load_json(DATA_DIR / "sca.json")

    combined = []

    # ---------- SAST ----------
    for issue in sast.get("issues", []):
        combined.append({
            "source": "SAST",
            "rule_id": issue.get("rule"),
            "severity": issue.get("severity", "LOW").upper(),
            "location": f"{issue.get('component')}:{issue.get('line', 0)}",
            "description": issue.get("message")
        })

    # ---------- DAST ----------
    for alert in extract_dast_alerts(dast):
        combined.append({
            "source": "DAST",
            "rule_id": alert.get("alert"),
            "severity": (alert.get("risk") or "LOW").upper(),
            "location": alert.get("url"),
            "description": alert.get("description")
        })

    # ---------- SCA ----------
    for v in extract_sca(sca):
        loc = " > ".join(v.get("from", [])) if v.get("from") else v.get("name")

        combined.append({
            "source": "SCA",
            "rule_id": v.get("id"),
            "severity": v.get("severity", "LOW").upper(),
            "location": loc,
            "description": v.get("title")
        })

    OUTPUT_FILE.write_text(json.dumps(combined, indent=2), encoding="utf-8")

    print(f"[ASTF] ✅ Combined ASTF file created: {OUTPUT_FILE}")
    print(f"[ASTF] ✅ Total merged alerts: {len(combined)}")


if __name__ == "__main__":
    main()

import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_FILE = os.path.join(BASE_DIR, "combined_astf.json")

FILES = ["sast.json", "dast.json", "sca.json"]

def load_json_safe(path):
    if not os.path.exists(path):
        print(f"[WARN] Missing file: {os.path.basename(path)}")
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "issues" in data:
                return data["issues"]
            if isinstance(data, dict) and "alerts" in data:
                return data["alerts"]
            if isinstance(data, dict) and "vulnerabilities" in data:
                return data["vulnerabilities"]
            return []
    except Exception:
        print(f"[WARN] Empty or invalid JSON: {os.path.basename(path)}")
        return []

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    combined = []

    print("[ASTF] Loading SAST, DAST & SCA JSON files...")

    for fname in FILES:
        path = os.path.join(DATA_DIR, fname)
        data = load_json_safe(path)
        combined.extend(data)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(combined, f, indent=2)

    print(f"[ASTF] ✅ Combined ASTF file created: {OUTPUT_FILE}")
    print(f"[ASTF] ✅ Total merged alerts: {len(combined)}")

if __name__ == "__main__":
    main()

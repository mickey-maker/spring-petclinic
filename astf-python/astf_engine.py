import json
import hashlib
from pathlib import Path

import pandas as pd

# ================================
# CONFIGURATION
# ================================

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)

# Tool encoding for your thesis (SAST=1, DAST=2, SCA=3)
TOOL_ENCODING = {
    "SAST": 1,
    "DAST": 2,
    "SCA": 3,
}

# Severity to numeric scale (for normalized severity)
SEVERITY_MAP = {
    "CRITICAL": 4,
    "MAJOR": 3,   # Sonar "MAJOR" treated like HIGH
    "HIGH": 3,
    "MEDIUM": 2,
    "MINOR": 1,
    "LOW": 1,
    "INFO": 0,
}


# ================================
# LOAD COMBINED ASTF
# ================================

def load_combined(path: str = "combined_astf.json") -> pd.DataFrame:
    file_path = BASE_DIR / path
    if not file_path.exists():
        raise FileNotFoundError(
            f"{file_path} not found. Run json_combiner.py first to generate it."
        )

    data = json.loads(file_path.read_text(encoding="utf-8"))
    df = pd.DataFrame(data)

    # Clean / normalize basic columns
    df["source"] = df["source"].fillna("SAST").str.upper()
    df["rule_id"] = df["rule_id"].fillna("UNKNOWN")
    df["severity_raw"] = df["severity"].fillna("LOW").str.upper()
    df["location"] = df["location"].fillna("UNKNOWN")
    df["description"] = df["description"].fillna("")

    # Tool encoding (SAST=1, DAST=2, SCA=3)
    df["tool_code"] = df["source"].map(TOOL_ENCODING).fillna(0).astype(int)

    # Severity normalization
    df["severity_norm"] = df["severity_raw"].map(SEVERITY_MAP).fillna(1).astype(int)

    return df


# ================================
# DEDUP KEY (PER-LOCATION)
# ================================

def build_dedup_key(row: pd.Series) -> str:
    """
    Deduplicate by:
      - source (SAST/DAST/SCA)
      - rule_id (same vulnerability rule)
      - location (file:line or URL)

    This means:
    - Same rule + same exact location -> considered duplicate
    - Same rule but *different* line or URL -> stays as separate alert
    """
    base = f"{row['source']}|{row['rule_id']}|{row['location']}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:18]


# ================================
# SUPPRESSION RULE (HEURISTIC)
# ================================

def suppression_rule(row: pd.Series) -> bool:
    loc = str(row["location"]).lower()
    desc = str(row["description"]).lower()

    # Example heuristic suppressions (you can refine later):
    # 1. Anything in test folders
    if "src/test" in loc or "test.java" in loc:
        return True

    # 2. Messages that clearly look like demo/sample
    if "sample" in desc or "demo" in desc:
        return True

    return False


# ================================
# TRIAGE ENGINE
# ================================

def run_triage(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # 1. Apply suppression
    df["suppressed"] = df.apply(suppression_rule, axis=1)

    # 2. Dedup key
    df["dedup_key"] = df.apply(build_dedup_key, axis=1)

    # 3. Risk score: function of severity + tool encoding
    #    (you can mention in thesis: "score = severity_norm * 20 + tool_code * 10")
    df["risk_score"] = df["severity_norm"] * 20 + df["tool_code"] * 10

    # 4. Suppressed alerts get risk score 0
    df.loc[df["suppressed"], "risk_score"] = 0

    # 5. Map risk_score to triage priority
    def map_priority(row):
        if row["suppressed"] or row["risk_score"] == 0:
            return "SUPPRESSED"
        score = row["risk_score"]
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        return "LOW"

    df["priority"] = df.apply(map_priority, axis=1)

    # 6. Deduplicate: keep the highest-risk alert per dedup_key
    df = df.sort_values("risk_score", ascending=False)
    df = df.drop_duplicates(subset="dedup_key", keep="first").reset_index(drop=True)

    # 7. Deterministic ART (Alert Resolution Time) in minutes (simulated)
    #    This is for your ART metric. You can tweak these numbers.
    art_map = {
        "CRITICAL": 30,
        "HIGH": 60,
        "MEDIUM": 180,
        "LOW": 480,
        "SUPPRESSED": 5,
    }
    df["ART_minutes"] = df["priority"].map(art_map).fillna(480).astype(int)

    # 8. Expected priority from severity_norm (for Prioritization Accuracy)
    def expected_priority(sev: int) -> str:
        if sev >= 4:
            return "CRITICAL"
        if sev == 3:
            return "HIGH"
        if sev == 2:
            return "MEDIUM"
        return "LOW"

    df["expected_priority"] = df["severity_norm"].apply(expected_priority)

    return df


# ================================
# METRICS ENGINE
# ================================

def compute_metrics(df: pd.DataFrame) -> dict:
    total = len(df)
    if total == 0:
        return {
            "total_alerts": 0,
            "suppressed_alerts": 0,
            "false_positive_rate": 0.0,
            "average_ART_minutes": 0.0,
            "prioritization_accuracy": 0.0,
            "priority_distribution": {},
            "source_distribution": {},
        }

    suppressed = int(df["suppressed"].sum())

    # FPR ~ proportion of alerts suppressed by ASTF
    false_positive_rate = round(suppressed / total, 4)

    # Average ART only on non-suppressed alerts
    non_supp = df[~df["suppressed"]]
    avg_art = round(non_supp["ART_minutes"].mean(), 2) if len(non_supp) > 0 else 0.0

    # Prioritization Accuracy: how often ASTF priority matches expected_priority
    if len(non_supp) > 0:
        correct = (non_supp["priority"] == non_supp["expected_priority"]).sum()
        prioritization_accuracy = round(correct / len(non_supp), 4)
    else:
        prioritization_accuracy = 0.0

    metrics = {
        "total_alerts": int(total),
        "suppressed_alerts": suppressed,
        "false_positive_rate": false_positive_rate,
        "average_ART_minutes": avg_art,
        "prioritization_accuracy": prioritization_accuracy,
        "priority_distribution": df["priority"].value_counts().to_dict(),
        "source_distribution": df["source"].value_counts().to_dict(),
    }

    return metrics


# ================================
# MAIN PIPELINE
# ================================

def main():
    print("[ASTF] Loading combined ASTF data...")
    df = load_combined("combined_astf.json")

    print("[ASTF] Running triage...")
    df_triaged = run_triage(df)

    print("[ASTF] Computing metrics...")
    metrics = compute_metrics(df_triaged)

    # Save detailed results
    df_triaged.to_csv(OUTPUT_DIR / "triage_results.csv", index=False)
    df_triaged.to_json(OUTPUT_DIR / "triage_results.json", orient="records", indent=2)

    # Save metrics JSON for thesis Chapter 5
    metrics_path = OUTPUT_DIR / "triage_metrics.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("[ASTF] ✅ Results written to:")
    print(f"   - {OUTPUT_DIR / 'triage_results.csv'}")
    print(f"   - {OUTPUT_DIR / 'triage_results.json'}")
    print(f"   - {metrics_path}")

    print("\n=== ASTF METRICS SUMMARY ===")
    for k, v in metrics.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()

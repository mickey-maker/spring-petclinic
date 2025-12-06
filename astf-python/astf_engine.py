import json
import os
import pandas as pd

INPUT_FILE = "astf-python/combined_astf.json"
OUTPUT_DIR = "astf-python/output"


# ===============================
# AUTO-DETECT + NORMALISE
# ===============================
def load_combined(path):
    print("[ASTF] Loading combined ASTF data...")

    if not os.path.exists(path):
        print("[ERROR] combined_astf.json not found!")
        return pd.DataFrame()

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not raw:
        print("[WARN] combined_astf.json is EMPTY!")
        return pd.DataFrame()

    normalised = []

    for item in raw:

        # ✅ AUTO-DETECT TOOL
        tool = item.get("tool") or item.get("source") or item.get("engine") or "UNKNOWN"

        # ✅ AUTO-DETECT TYPE
        issue_type = (
                item.get("type")
                or item.get("issueType")
                or item.get("category")
                or "VULNERABILITY"
        )

        # ✅ AUTO-DETECT SEVERITY
        severity = (
                item.get("severity")
                or item.get("risk")
                or item.get("priority")
                or "INFO"
        )

        # ✅ AUTO-DETECT MESSAGE
        message = (
                item.get("message")
                or item.get("title")
                or item.get("desc")
                or "No description"
        )

        # ✅ AUTO-DETECT FILE / URL
        file = (
                item.get("file")
                or item.get("component")
                or item.get("url")
                or "UNKNOWN"
        )

        # ✅ AUTO-DETECT RULE ID
        rule = (
                item.get("rule")
                or item.get("pluginid")
                or item.get("id")
                or "UNKNOWN"
        )

        normalised.append({
            "tool": str(tool).upper(),
            "type": str(issue_type).upper(),
            "severity": str(severity).upper(),
            "message": message,
            "file": file,
            "rule": rule
        })

    df = pd.DataFrame(normalised)

    print("[ASTF] ✅ Alerts loaded:", len(df))
    return df


# ===============================
# PRIORITY SCORING
# ===============================
def apply_priority_scoring(df):
    print("[ASTF] Applying priority scoring...")

    SEVERITY_WEIGHT = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1
    }

    TYPE_WEIGHT = {
        "VULNERABILITY": 5,
        "BUG": 3,
        "CODE_SMELL": 1
    }

    df["sev_score"] = df["severity"].map(SEVERITY_WEIGHT).fillna(1)
    df["type_score"] = df["type"].map(TYPE_WEIGHT).fillna(1)

    df["final_score"] = df["sev_score"] * df["type_score"]

    def assign_priority(score):
        if score >= 20:
            return "CRITICAL"
        elif score >= 12:
            return "HIGH"
        elif score >= 6:
            return "MEDIUM"
        else:
            return "LOW"

    df["priority"] = df["final_score"].apply(assign_priority)

    print("[ASTF] ✅ Priority scoring complete")
    return df


# ===============================
# DEDUPLICATION
# ===============================
def deduplicate_alerts(df):
    print("[ASTF] Removing duplicate alerts...")

    before = len(df)

    df = df.drop_duplicates(
        subset=["tool", "type", "rule", "file"]
    )

    after = len(df)

    print(f"[ASTF] ✅ Deduplication: {before} → {after}")
    return df


# ===============================
# METRICS
# ===============================
def generate_metrics(df):
    print("[ASTF] Generating ASTF metrics...")

    metrics = {
        "total_alerts": int(len(df)),
        "alerts_by_tool": df["tool"].value_counts().to_dict(),
        "alerts_by_type": df["type"].value_counts().to_dict(),
        "alerts_by_severity": df["severity"].value_counts().to_dict(),
        "alerts_by_priority": df["priority"].value_counts().to_dict(),
    }

    # ✅ False Positive proxy
    fp = df[df["priority"] == "LOW"]
    metrics["false_positive_estimate"] = int(len(fp))
    metrics["false_positive_rate"] = round((len(fp) / len(df)) * 100, 2) if len(df) else 0

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "triage_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("[ASTF] ✅ Metrics generated")
    return metrics


# ===============================
# SAVE OUTPUTS
# ===============================
def save_outputs(df, metrics):
    print("[ASTF] Saving outputs...")

    df.to_csv(os.path.join(OUTPUT_DIR, "astf_final_results.csv"), index=False)
    df["priority"].value_counts().to_csv(os.path.join(OUTPUT_DIR, "priority_summary.csv"))
    df["tool"].value_counts().to_csv(os.path.join(OUTPUT_DIR, "tool_summary.csv"))
    df["type"].value_counts().to_csv(os.path.join(OUTPUT_DIR, "type_summary.csv"))

    print("[ASTF] ✅ All output files saved")


# ===============================
# MAIN
# ===============================
def main():
    df = load_combined(INPUT_FILE)

    if df.empty:
        print("[ASTF] ❌ No alerts detected. STOPPING.")
        return

    df = deduplicate_alerts(df)
    df = apply_priority_scoring(df)
    metrics = generate_metrics(df)
    save_outputs(df, metrics)

    print("\n✅ ASTF PIPELINE SUCCESSFUL")
    print("Final Alert Count:", len(df))
    print(df["priority"].value_counts())


if __name__ == "__main__":
    main()

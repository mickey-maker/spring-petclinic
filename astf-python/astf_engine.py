import json
import os
import pandas as pd

INPUT_FILE = "astf-python/combined_astf.json"
OUTPUT_DIR = "astf-python/output"

# ===============================
# LOAD COMBINED ASTF DATA
# ===============================
def load_combined(path):
    print("[ASTF] Loading combined ASTF data...")

    if not os.path.exists(path):
        print("[ERROR] combined_astf.json not found!")
        return pd.DataFrame()

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not data:
        print("[WARN] combined_astf.json is EMPTY!")
        return pd.DataFrame()

    df = pd.DataFrame(data)

    # ✅ Ensure required columns always exist
    df["tool"] = df.get("tool", "UNKNOWN")
    df["type"] = df.get("type", "UNKNOWN")
    df["severity"] = df.get("severity", "INFO")
    df["message"] = df.get("message", "")
    df["file"] = df.get("file", "")
    df["rule"] = df.get("rule", "")

    print("[ASTF] ✅ Data loaded successfully!")
    print("[ASTF] ✅ Total alerts received:", len(df))

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

    df["sev_score"] = df["severity"].str.upper().map(SEVERITY_WEIGHT).fillna(1)
    df["type_score"] = df["type"].str.upper().map(TYPE_WEIGHT).fillna(1)

    df["final_score"] = df["sev_score"] * df["type_score"]

    # ✅ Priority Label
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

    print("[ASTF] ✅ Priority scoring completed")
    return df


# ===============================
# DEDUPLICATION & SUPPRESSION
# ===============================
def deduplicate_alerts(df):
    print("[ASTF] Removing duplicate alerts...")

    before = len(df)

    df = df.drop_duplicates(
        subset=["tool", "type", "rule", "file"]
    )

    after = len(df)

    print(f"[ASTF] ✅ Deduplication completed: {before} → {after}")
    return df


# ===============================
# METRICS GENERATION
# ===============================
def generate_metrics(df):
    print("[ASTF] Generating ASTF Metrics...")

    metrics = {}

    # ✅ Total Alerts
    metrics["total_alerts"] = int(len(df))

    # ✅ Alerts by Tool
    metrics["alerts_by_tool"] = df["tool"].value_counts().to_dict()

    # ✅ Alerts by Type
    metrics["alerts_by_type"] = df["type"].value_counts().to_dict()

    # ✅ Alerts by Severity
    metrics["alerts_by_severity"] = df["severity"].value_counts().to_dict()

    # ✅ Alerts by Priority
    metrics["alerts_by_priority"] = df["priority"].value_counts().to_dict()

    # ✅ False Positive Proxy (Heuristic)
    false_positive_estimate = df[df["priority"] == "LOW"]
    metrics["false_positive_estimate"] = int(len(false_positive_estimate))
    metrics["false_positive_rate"] = round(
        (len(false_positive_estimate) / len(df)) * 100, 2
    ) if len(df) != 0 else 0

    # ✅ Save Metrics
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "triage_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("[ASTF] ✅ Metrics generated successfully!")
    return metrics


# ===============================
# SAVE OUTPUT FILES
# ===============================
def save_outputs(df, metrics):
    print("[ASTF] Saving final outputs...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ✅ Full Result
    df.to_csv(os.path.join(OUTPUT_DIR, "astf_final_results.csv"), index=False)

    # ✅ Priority Summary
    df["priority"].value_counts().to_csv(
        os.path.join(OUTPUT_DIR, "priority_summary.csv")
    )

    # ✅ Tool Summary
    df["tool"].value_counts().to_csv(
        os.path.join(OUTPUT_DIR, "tool_summary.csv")
    )

    # ✅ Type Summary (BUG / VULN / CODE SMELL)
    df["type"].value_counts().to_csv(
        os.path.join(OUTPUT_DIR, "type_summary.csv")
    )

    print("[ASTF] ✅ All outputs saved successfully!")


# ===============================
# MAIN CONTROLLER
# ===============================
def main():
    df = load_combined(INPUT_FILE)

    if df.empty:
        print("[ASTF] ❌ No alerts to process. Pipeline stopped.")
        return

    df = deduplicate_alerts(df)
    df = apply_priority_scoring(df)
    metrics = generate_metrics(df)
    save_outputs(df, metrics)

    print("\n===============================")
    print("✅ ASTF TRIAGE COMPLETED SUCCESSFULLY")
    print("===============================")
    print("Final Alert Count:", len(df))
    print("Priority Distribution:")
    print(df["priority"].value_counts())


if __name__ == "__main__":
    main()

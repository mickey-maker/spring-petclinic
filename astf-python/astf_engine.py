import json
import os
import pandas as pd

INPUT_FILE = "astf-python/combined_astf.json"
RAW_DATA_DIR = "astf-python/data"
OUTPUT_DIR = "astf-python/output"


# ===============================
# LOAD & NORMALISE ASTF DATA
# ===============================
def load_combined(path):
    if not os.path.exists(path):
        print("[ERROR] combined_astf.json not found!")
        return pd.DataFrame()

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not raw:
        return pd.DataFrame()

    rows = []
    for item in raw:
        rows.append({
            "tool": item.get("tool", "").upper(),
            "type": item.get("type", "").upper(),
            "severity": item.get("severity", "").upper(),
            "message": item.get("message", ""),
            "file": item.get("file", ""),
            "rule": item.get("rule", "")
        })

    return pd.DataFrame(rows)


# ===============================
# PRIORITY SCORING
# ===============================
def apply_priority_scoring(df):
    SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    TYPE_WEIGHT = {"VULNERABILITY": 5, "BUG": 3, "CODE_SMELL": 1}

    df["sev_score"] = df["severity"].map(SEV_WEIGHT).fillna(1)
    df["type_score"] = df["type"].map(TYPE_WEIGHT).fillna(1)
    df["final_score"] = df["sev_score"] * df["type_score"]

    def assign(score):
        if score >= 20: return "CRITICAL"
        if score >= 12: return "HIGH"
        if score >= 6: return "MEDIUM"
        return "LOW"

    df["priority"] = df["final_score"].apply(assign)
    return df


# ===============================
# DEDUPLICATION
# ===============================
def deduplicate_alerts(df):
    return df.drop_duplicates(subset=["tool", "type", "rule", "file"])


# ===============================
# METRICS → DF
# ===============================
def generate_metrics_df(df):
    fp = len(df[df["priority"] == "LOW"])
    total = len(df)

    metrics = {
        "total_alerts": [total],
        "alerts_by_tool": [df["tool"].value_counts().to_dict()],
        "alerts_by_type": [df["type"].value_counts().to_dict()],
        "alerts_by_severity": [df["severity"].value_counts().to_dict()],
        "alerts_by_priority": [df["priority"].value_counts().to_dict()],
        "false_positive_estimate": [fp],
        "false_positive_rate": [round((fp / total) * 100, 2) if total > 0 else 0]
    }

    return pd.DataFrame(metrics)


# ===============================
# RAW JSON → DF
# ===============================
def load_raw_json(filename):
    path = os.path.join(RAW_DATA_DIR, filename)
    if not os.path.exists(path):
        return pd.DataFrame([{"error": f"{filename} missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    return pd.json_normalize(raw)


# ===============================
# WRITE EXCEL WITH MULTIPLE SHEETS
# ===============================
def save_excel(
        astf_df, priority_df, tool_df, type_df,
        metrics_df, sast_df, dast_df, sca_df
):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "astf_master_final.xlsx")

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        astf_df.to_excel(writer, sheet_name="ASTF_FINAL", index=False)
        priority_df.to_excel(writer, sheet_name="PRIORITY_SUMMARY", index=False)
        tool_df.to_excel(writer, sheet_name="TOOL_SUMMARY", index=False)
        type_df.to_excel(writer, sheet_name="TYPE_SUMMARY", index=False)
        metrics_df.to_excel(writer, sheet_name="TRIAGE_METRICS", index=False)
        sast_df.to_excel(writer, sheet_name="SAST_RAW", index=False)
        dast_df.to_excel(writer, sheet_name="DAST_RAW", index=False)
        sca_df.to_excel(writer, sheet_name="SCA_RAW", index=False)

    print("[ASTF] ✅ Excel workbook created:", output_path)


# ===============================
# MAIN WORKFLOW
# ===============================
def main():
    df = load_combined(INPUT_FILE)
    df = deduplicate_alerts(df)
    df = apply_priority_scoring(df)

    metrics_df = generate_metrics_df(df)

    priority_df = df["priority"].value_counts().reset_index()
    tool_df = df["tool"].value_counts().reset_index()
    type_df = df["type"].value_counts().reset_index()

    sast_df = load_raw_json("sast.json")
    dast_df = load_raw_json("dast.json")
    sca_df = load_raw_json("sca.json")

    save_excel(df, priority_df, tool_df, type_df, metrics_df, sast_df, dast_df, sca_df)


if __name__ == "__main__":
    main()

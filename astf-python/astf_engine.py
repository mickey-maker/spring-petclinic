import json
import os
import pandas as pd
from openpyxl import load_workbook
from openpyxl.chart import PieChart, Reference

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
            "tool": str(item.get("tool", "")).upper(),
            "type": str(item.get("type", "")).upper(),
            "severity": str(item.get("severity", "")).upper(),
            "message": item.get("message", ""),
            "file": item.get("file", ""),
            "rule": item.get("rule", "")
        })

    print("[ASTF] ✅ ASTF alerts loaded:", len(rows))
    return pd.DataFrame(rows)


# ===============================
# DEDUPLICATION
# ===============================
def deduplicate_alerts(df):
    before = len(df)
    df = df.drop_duplicates(subset=["tool", "type", "rule", "file"])
    after = len(df)
    print(f"[ASTF] ✅ Deduplication: {before} → {after}")
    return df


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
    print("[ASTF] ✅ Priority scoring completed")
    return df


# ===============================
# TRIAGE METRICS → DF
# ===============================
def generate_metrics_df(df):
    total = len(df)
    fp = len(df[df["priority"] == "LOW"])

    metrics = {
        "Metric": [
            "Total Alerts",
            "False Positive Estimate",
            "False Positive Rate (%)"
        ],
        "Value": [
            total,
            fp,
            round((fp / total) * 100, 2) if total > 0 else 0
        ]
    }

    return pd.DataFrame(metrics)


# ===============================
# RAW JSON → FULL LIST DF
# ===============================
def load_raw_json(filename):
    path = os.path.join(RAW_DATA_DIR, filename)
    if not os.path.exists(path):
        print(f"[WARN] {filename} not found")
        return pd.DataFrame([{"error": f"{filename} missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    df = pd.json_normalize(raw)
    print(f"[ASTF] ✅ Loaded RAW list: {filename}")
    return df


# ===============================
# SAVE MAIN EXCEL FILE
# ===============================
def save_excel(astf_df, metrics_df, sast_df, dast_df, sca_df):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "astf_master_final.xlsx")

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        astf_df.to_excel(writer, sheet_name="ASTF_FINAL", index=False)
        metrics_df.to_excel(writer, sheet_name="TRIAGE_METRICS", index=False)
        sast_df.to_excel(writer, sheet_name="SAST_RAW_LIST", index=False)
        dast_df.to_excel(writer, sheet_name="DAST_RAW_LIST", index=False)
        sca_df.to_excel(writer, sheet_name="SCA_RAW_LIST", index=False)

    print("[ASTF] ✅ Base Excel file created:", output_path)


# ===============================
# SUMMARY DASHBOARD + PIE CHARTS
# ===============================
def create_summary_dashboard(df, excel_path):
    print("[ASTF] Creating SUMMARY DASHBOARD with pie charts...")

    priority_summary = df["priority"].value_counts().reset_index()
    priority_summary.columns = ["Priority", "Count"]

    tool_summary = df["tool"].value_counts().reset_index()
    tool_summary.columns = ["Tool", "Count"]

    type_summary = df["type"].value_counts().reset_index()
    type_summary.columns = ["Type", "Count"]

    # ✅ REPLACE dashboard safely if it already exists
    with pd.ExcelWriter(
            excel_path,
            engine="openpyxl",
            mode="a",
            if_sheet_exists="replace"
    ) as writer:

        priority_summary.to_excel(writer, sheet_name="SUMMARY_DASHBOARD", startrow=0, index=False)
        tool_summary.to_excel(
            writer,
            sheet_name="SUMMARY_DASHBOARD",
            startrow=priority_summary.shape[0] + 3,
            index=False
        )
        type_summary.to_excel(
            writer,
            sheet_name="SUMMARY_DASHBOARD",
            startrow=priority_summary.shape[0] + tool_summary.shape[0] + 6,
            index=False
        )

    wb = load_workbook(excel_path)
    ws = wb["SUMMARY_DASHBOARD"]

    # === PIE 1: PRIORITY ===
    pie1 = PieChart()
    labels1 = Reference(ws, min_col=1, min_row=2, max_row=priority_summary.shape[0] + 1)
    data1 = Reference(ws, min_col=2, min_row=1, max_row=priority_summary.shape[0] + 1)
    pie1.add_data(data1, titles_from_data=True)
    pie1.set_categories(labels1)
    pie1.title = "Priority Distribution"
    ws.add_chart(pie1, "E2")

    # === PIE 2: TOOL ===
    start_tool = priority_summary.shape[0] + 4
    pie2 = PieChart()
    labels2 = Reference(ws, min_col=1, min_row=start_tool + 1, max_row=start_tool + tool_summary.shape[0])
    data2 = Reference(ws, min_col=2, min_row=start_tool, max_row=start_tool + tool_summary.shape[0])
    pie2.add_data(data2, titles_from_data=True)
    pie2.set_categories(labels2)
    pie2.title = "Tool Distribution"
    ws.add_chart(pie2, "E18")

    # === PIE 3: TYPE ===
    start_type = priority_summary.shape[0] + tool_summary.shape[0] + 7
    pie3 = PieChart()
    labels3 = Reference(ws, min_col=1, min_row=start_type + 1, max_row=start_type + type_summary.shape[0])
    data3 = Reference(ws, min_col=2, min_row=start_type, max_row=start_type + type_summary.shape[0])
    pie3.add_data(data3, titles_from_data=True)
    pie3.set_categories(labels3)
    pie3.title = "Type Distribution"
    ws.add_chart(pie3, "E34")

    wb.save(excel_path)
    print("[ASTF] ✅ SUMMARY DASHBOARD + PIE CHARTS CREATED")


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

    metrics_df = generate_metrics_df(df)

    sast_df = load_raw_json("sast.json")
    dast_df = load_raw_json("dast.json")
    sca_df = load_raw_json("sca.json")

    save_excel(df, metrics_df, sast_df, dast_df, sca_df)

    excel_path = os.path.join(OUTPUT_DIR, "astf_master_final.xlsx")
    create_summary_dashboard(df, excel_path)

    print("\n✅ ASTF PIPELINE SUCCESSFUL")
    print("✅ Final ASTF Alerts:", len(df))


if __name__ == "__main__":
    main()

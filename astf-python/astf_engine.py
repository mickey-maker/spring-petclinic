import json
import os
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Border, Side

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
# ✅ FULL RAW JSON → FULL LIST DF
# ===============================
def load_raw_json(filename):
    path = os.path.join(RAW_DATA_DIR, filename)

    if not os.path.exists(path):
        print(f"[WARN] {filename} not found")
        return pd.DataFrame([{"error": f"{filename} missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if "issues" in raw:
        df = pd.json_normalize(raw["issues"])
        print("[ASTF] ✅ Loaded FULL SAST issue list")

    elif "site" in raw:
        alerts = []
        for site in raw.get("site", []):
            alerts.extend(site.get("alerts", []))
        df = pd.json_normalize(alerts)
        print("[ASTF] ✅ Loaded FULL DAST alert list")

    elif "vulnerabilities" in raw:
        df = pd.json_normalize(raw["vulnerabilities"])
        print("[ASTF] ✅ Loaded FULL SCA vulnerability list")

    else:
        df = pd.json_normalize(raw)
        print("[ASTF] ✅ Loaded RAW JSON (generic format)")

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
# ✅ SUMMARY DASHBOARD (TABLE FORMAT ONLY)
# ===============================
def create_summary_dashboard(df, excel_path):
    print("[ASTF] Creating SUMMARY DASHBOARD (FINAL TABLE FORMAT)...")

    priority_summary = df["priority"].value_counts().reset_index()
    priority_summary.columns = ["PRIORITY", "COUNT"]

    tool_summary = df["tool"].value_counts().reset_index()
    tool_summary.columns = ["TOOL", "COUNT"]

    type_summary = df["type"].value_counts().reset_index()
    type_summary.columns = ["TYPE", "COUNT"]

    dashboard_rows = []

    dashboard_rows.append(["PRIORITY", "COUNT"])
    dashboard_rows.extend(priority_summary.values.tolist())
    dashboard_rows.append(["", ""])

    dashboard_rows.append(["TOOL", "COUNT"])
    dashboard_rows.extend(tool_summary.values.tolist())
    dashboard_rows.append(["", ""])

    dashboard_rows.append(["TYPE", "COUNT"])
    dashboard_rows.extend(type_summary.values.tolist())

    dashboard_df = pd.DataFrame(dashboard_rows, columns=["CATEGORY", "VALUE"])

    wb = load_workbook(excel_path)
    if "SUMMARY_DASHBOARD" in wb.sheetnames:
        del wb["SUMMARY_DASHBOARD"]
    wb.save(excel_path)

    with pd.ExcelWriter(excel_path, engine="openpyxl", mode="a") as writer:
        dashboard_df.to_excel(writer, sheet_name="SUMMARY_DASHBOARD", index=False)

    print("[ASTF] ✅ SUMMARY DASHBOARD CREATED (PRIORITY + TOOL + TYPE VISIBLE)")


# ===============================
# ✅ APPLY LIGHT GREY + BORDERS TO ALL TABLE HEADERS
# ===============================
def apply_global_formatting(excel_path):
    print("[ASTF] Applying global table formatting...")

    wb = load_workbook(excel_path)

    grey_fill = PatternFill(start_color="EDEDED", end_color="EDEDED", fill_type="solid")
    bold_font = Font(bold=True)
    thin_border = Border(
        left=Side(style="thin"),
        right=Side(style="thin"),
        top=Side(style="thin"),
        bottom=Side(style="thin")
    )

    for sheet in wb.sheetnames:
        ws = wb[sheet]

        # ✅ Format FIRST ROW (header)
        for cell in ws[1]:
            cell.font = bold_font
            cell.fill = grey_fill
            cell.border = thin_border

        # ✅ Apply borders to all populated cells
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                if cell.value is not None:
                    cell.border = thin_border

    wb.save(excel_path)
    print("[ASTF] ✅ Global formatting applied to ALL sheets")


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

    apply_global_formatting(excel_path)

    print("\n✅ ASTF PIPELINE SUCCESSFUL")
    print("✅ Final ASTF Alerts:", len(df))


if __name__ == "__main__":
    main()

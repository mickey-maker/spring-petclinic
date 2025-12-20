import json
import os
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Border, Side

INPUT_FILE = "astf-python/combined_astf.json"
RAW_DATA_DIR = "astf-python/data"
OUTPUT_DIR = "astf-python/output"

SUPPRESS_LIST = "astf-python/suppress_list.csv"


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
            "tool": str(item.get("tool", "")).upper().strip(),
            "type": str(item.get("type", "")).upper().strip(),
            "severity": str(item.get("severity", "")).upper().strip(),
            "message": item.get("message", ""),
            "file": str(item.get("file", "")).strip(),
            "rule": str(item.get("rule", "")).strip()
        })

    print("[ASTF] ✅ ASTF alerts loaded:", len(rows))
    return pd.DataFrame(rows)


def deduplicate_alerts(df):
    before = len(df)
    df = df.drop_duplicates(subset=["tool", "type", "rule", "file"])
    after = len(df)
    print(f"[ASTF] ✅ Deduplication: {before} → {after}")
    return df


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


# ✅ Auto-generate suppression list (safe with localhost DAST)
def auto_generate_suppress_list(df, output_path=SUPPRESS_LIST):
    """
    Conservative suppression rules to estimate false positives / accepted risks.

    - SAST: suppress CODE_SMELL (quality issue) and INFO severity
    - SCA: suppress INFO severity
    - DAST: suppress only INFO severity (DO NOT suppress localhost just because it's localhost,
            since your DAST runs on 127.0.0.1 inside GitHub Actions) :contentReference[oaicite:4]{index=4}
    - Any tool: suppress if priority == LOW (optional noise reduction proxy)
    """
    suppressed_rows = []

    for _, row in df.iterrows():
        tool = row["tool"]
        sev = row["severity"]
        typ = row["type"]
        pri = row["priority"]

        reason = None

        # 1) Informational severity (safe)
        if sev == "INFO":
            reason = "Informational severity (non-actionable)"

        # 2) SAST Code Smell (safe)
        elif tool == "SAST" and typ == "CODE_SMELL":
            reason = "Code smell (quality issue)"

        # 3) LOW priority (noise proxy) - keep it if you want stronger reduction
        elif pri == "LOW":
            reason = "Low priority noise"

        # NOTE: We intentionally DO NOT suppress DAST localhost endpoints, because
        # your YAML scans 127.0.0.1:8080 in runner :contentReference[oaicite:5]{index=5}.

        if reason:
            suppressed_rows.append({
                "tool": row["tool"],
                "rule": row["rule"],
                "file": row["file"],
                "reason": reason
            })

    sup_df = pd.DataFrame(suppressed_rows)
    if sup_df.empty:
        sup_df = pd.DataFrame(columns=["tool", "rule", "file", "reason"])

    sup_df.drop_duplicates(subset=["tool", "rule", "file"], inplace=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    sup_df.to_csv(output_path, index=False)

    print(f"[ASTF] ✅ Auto-generated suppress_list.csv: {output_path}")
    print(f"[ASTF] ✅ Suppress rules matched: {len(sup_df)} alerts")


def apply_suppression(df):
    df["suppressed"] = False
    df["suppress_reason"] = ""

    if not os.path.exists(SUPPRESS_LIST):
        print("[ASTF] ⚠️ suppress_list.csv not found → Estimated FPR will be N/A.")
        return df

    sup = pd.read_csv(SUPPRESS_LIST)

    required = ["tool", "rule", "file"]
    for col in required:
        if col not in sup.columns:
            raise ValueError(f"[ERROR] suppress_list.csv missing required column: {col}")

    if "reason" not in sup.columns:
        sup["reason"] = ""

    sup["tool"] = sup["tool"].astype(str).str.upper().str.strip()
    sup["rule"] = sup["rule"].astype(str).str.strip()
    sup["file"] = sup["file"].astype(str).str.strip()
    sup["reason"] = sup["reason"].astype(str).str.strip()

    df["tool"] = df["tool"].astype(str).str.upper().str.strip()
    df["rule"] = df["rule"].astype(str).str.strip()
    df["file"] = df["file"].astype(str).str.strip()

    df["__key"] = df["tool"] + "|" + df["rule"] + "|" + df["file"]
    sup["__key"] = sup["tool"] + "|" + sup["rule"] + "|" + sup["file"]

    reason_map = dict(zip(sup["__key"], sup["reason"]))
    suppress_keys = set(sup["__key"].tolist())

    df["suppressed"] = df["__key"].isin(suppress_keys)
    df["suppress_reason"] = df["__key"].map(reason_map).fillna("")

    df.drop(columns=["__key"], inplace=True, errors="ignore")

    print(f"[ASTF] ✅ Suppression applied: {int(df['suppressed'].sum())} alerts suppressed")
    return df


def generate_metrics_df(df):
    total = len(df)
    suppressed = int(df["suppressed"].sum()) if "suppressed" in df.columns else 0
    estimated_fpr = round((suppressed / total) * 100, 2) if total > 0 else 0

    metrics = {
        "Metric": [
            "Total Alerts",
            "Suppressed Alerts (Rule-Based)",
            "Estimated False Positive Rate (%)"
        ],
        "Value": [
            total,
            suppressed,
            estimated_fpr
        ]
    }
    return pd.DataFrame(metrics)


def load_raw_json(filename):
    path = os.path.join(RAW_DATA_DIR, filename)

    if not os.path.exists(path):
        print(f"[WARN] {filename} not found")
        return pd.DataFrame([{"error": f"{filename} missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if isinstance(raw, dict) and "issues" in raw:
        df = pd.json_normalize(raw["issues"])
        print("[ASTF] ✅ Loaded FULL SAST issue list")
    elif isinstance(raw, dict) and "site" in raw:
        alerts = []
        for site in raw.get("site", []):
            alerts.extend(site.get("alerts", []))
        df = pd.json_normalize(alerts)
        print("[ASTF] ✅ Loaded FULL DAST alert list")
    elif isinstance(raw, dict) and "vulnerabilities" in raw:
        df = pd.json_normalize(raw["vulnerabilities"])
        print("[ASTF] ✅ Loaded FULL SCA vulnerability list")
    else:
        df = pd.json_normalize(raw)
        print("[ASTF] ✅ Loaded RAW JSON (generic format)")

    return df


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

        for cell in ws[1]:
            cell.font = bold_font
            cell.fill = grey_fill
            cell.border = thin_border

        for row in ws.iter_rows(min_row=2):
            for cell in row:
                if cell.value is not None:
                    cell.border = thin_border

    wb.save(excel_path)
    print("[ASTF] ✅ Global formatting applied to ALL sheets")


def main():
    df = load_combined(INPUT_FILE)

    if df.empty:
        print("[ASTF] ❌ No alerts detected. STOPPING.")
        return

    df = deduplicate_alerts(df)
    df = apply_priority_scoring(df)

    # ✅ suppress_list.csv is generated here (automatic)
    auto_generate_suppress_list(df)

    # ✅ then applied to compute Estimated FPR
    df = apply_suppression(df)

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

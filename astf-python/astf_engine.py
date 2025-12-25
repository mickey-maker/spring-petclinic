import json
import os
import pandas as pd
from openpyxl import load_workbook
from openpyxl.styles import Font, PatternFill, Border, Side

INPUT_FILE = "astf-python/combined_astf.json"
RAW_DATA_DIR = "astf-python/data"
OUTPUT_DIR = "astf-python/output"

SUPPRESS_LIST_CSV = "astf-python/suppress_list.csv"


# ===============================
# HELPERS
# ===============================
def _to_int_or_none(val):
    try:
        if val is None:
            return None
        s = str(val).strip()
        if s == "" or s.lower() == "none":
            return None
        return int(float(s))
    except Exception:
        return None


def _safe_upper(x):
    return str(x or "").strip().upper()


def _safe_str(x):
    return str(x or "").strip()


# ===============================
# LOAD & NORMALISE ASTF DATA
# ===============================
def load_combined(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        print("[ERROR] combined_astf.json not found:", path)
        return pd.DataFrame()

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not raw:
        return pd.DataFrame()

    rows = []
    for item in raw:
        tool = _safe_upper(item.get("tool", ""))
        typ = _safe_upper(item.get("type", ""))
        severity = _safe_upper(item.get("severity", ""))
        message = item.get("message", "")
        rule = _safe_str(item.get("rule", ""))

        # file
        file_val = _safe_str(item.get("file", ""))

        # line:
        # ✅ supports:
        # - new format: line is int
        # - old/broken format: line was "file:123" or "uri"
        raw_line = item.get("line", None)
        line_val = _to_int_or_none(raw_line)

        if line_val is None and isinstance(raw_line, str) and ":" in raw_line:
            # try parse "...:123"
            try:
                maybe_line = raw_line.split(":")[-1].strip()
                parsed = _to_int_or_none(maybe_line)
                if parsed is not None:
                    line_val = parsed
                    # if file missing, try recover file from prefix
                    if not file_val:
                        file_val = ":".join(raw_line.split(":")[:-1]).strip()
            except Exception:
                pass

        # location (string)
        location = _safe_str(item.get("location", ""))
        if not location:
            location = f"{file_val}:{line_val}" if (file_val and line_val is not None) else file_val

        rows.append({
            "tool": tool,
            "type": typ,
            "severity": severity,
            "message": message,
            "file": file_val,
            "rule": rule,
            "line": line_val,          # ✅ int/None
            "location": location       # ✅ always string
        })

    print("[ASTF] ✅ ASTF alerts loaded:", len(rows))
    return pd.DataFrame(rows)


# ===============================
# DEDUPLICATION
# ===============================
def deduplicate_alerts(df: pd.DataFrame) -> pd.DataFrame:
    before = len(df)
    subset_cols = ["tool", "type", "rule", "file", "line"]
    df = df.drop_duplicates(subset=subset_cols)
    after = len(df)
    print(f"[ASTF] ✅ Deduplication: {before} → {after}")
    return df


# ===============================
# PRIORITY SCORING
# ===============================
def apply_priority_scoring(df: pd.DataFrame) -> pd.DataFrame:
    SEV_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    TYPE_WEIGHT = {"VULNERABILITY": 5, "BUG": 3, "CODE_SMELL": 1}

    df["sev_score"] = df["severity"].map(SEV_WEIGHT).fillna(1)
    df["type_score"] = df["type"].map(TYPE_WEIGHT).fillna(1)
    df["final_score"] = df["sev_score"] * df["type_score"]

    def assign(score):
        if score >= 20:
            return "CRITICAL"
        if score >= 12:
            return "HIGH"
        if score >= 6:
            return "MEDIUM"
        return "LOW"

    df["priority"] = df["final_score"].apply(assign)
    print("[ASTF] ✅ Priority scoring completed")
    return df


# ===============================
# AUTO-GENERATE suppress_list.csv
# ===============================
def auto_generate_suppress_list(df: pd.DataFrame, output_path: str = SUPPRESS_LIST_CSV) -> pd.DataFrame:
    """
    Generates suppress_list.csv using conservative rules (noise proxy).
    ✅ Includes file + line + location so you can show the exact code location/endpoint.

    Rule-based suppression (proxy for FPR):
    - INFO severity => suppress (non-actionable)
    - SAST CODE_SMELL => suppress (quality issue)
    - LOW priority => suppress (noise proxy)
    """
    suppressed_rows = []

    for _, row in df.iterrows():
        tool = row.get("tool", "")
        sev = row.get("severity", "")
        typ = row.get("type", "")
        pri = row.get("priority", "")
        rule = row.get("rule", "")
        file_ = row.get("file", "")
        line_ = row.get("line", None)
        location = row.get("location", file_)

        reason = None
        if sev == "INFO":
            reason = "Informational severity (non-actionable)"
        elif tool == "SAST" and typ == "CODE_SMELL":
            reason = "Code smell (quality issue)"
        elif pri == "LOW":
            reason = "Low priority noise"

        if reason:
            suppressed_rows.append({
                "tool": tool,
                "rule": rule,
                "file": file_,
                "line": line_,          # ✅ stored as int/None
                "location": location,   # ✅ stored as string
                "reason": reason
            })

    sup_df = pd.DataFrame(suppressed_rows)
    if sup_df.empty:
        sup_df = pd.DataFrame(columns=["tool", "rule", "file", "line", "location", "reason"])

    # ✅ suppression matching: tool/rule/file/line when line exists
    sup_df.drop_duplicates(subset=["tool", "rule", "file", "line"], inplace=True)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    sup_df.to_csv(output_path, index=False)

    print(f"[ASTF] ✅ suppress_list.csv generated: {output_path}")
    print(f"[ASTF] ✅ suppress_list.csv absolute path: {os.path.abspath(output_path)}")
    print(f"[ASTF] ✅ suppressed candidates: {len(sup_df)}")
    return sup_df


# ===============================
# APPLY SUPPRESSION USING suppress_list.csv
# ===============================
def apply_suppression(df: pd.DataFrame, suppress_csv: str = SUPPRESS_LIST_CSV) -> pd.DataFrame:
    df["suppressed"] = False
    df["suppress_reason"] = ""

    if not os.path.exists(suppress_csv):
        print("[ASTF] ⚠️ suppress_list.csv not found → suppression skipped.")
        print("[ASTF] ⚠️ expected at:", os.path.abspath(suppress_csv))
        return df

    sup = pd.read_csv(suppress_csv)

    required = ["tool", "rule", "file"]
    for col in required:
        if col not in sup.columns:
            raise ValueError(f"[ERROR] suppress_list.csv missing required column: {col}")

    if "line" not in sup.columns:
        sup["line"] = None
    if "reason" not in sup.columns:
        sup["reason"] = ""

    # Normalize
    sup["tool"] = sup["tool"].astype(str).str.upper().str.strip()
    sup["rule"] = sup["rule"].astype(str).str.strip()
    sup["file"] = sup["file"].astype(str).str.strip()
    sup["line"] = sup["line"].apply(_to_int_or_none)
    sup["reason"] = sup["reason"].astype(str).str.strip()

    df["tool"] = df["tool"].astype(str).str.upper().str.strip()
    df["rule"] = df["rule"].astype(str).str.strip()
    df["file"] = df["file"].astype(str).str.strip()
    df["line"] = df["line"].apply(_to_int_or_none)

    # ✅ key includes line when available (more accurate)
    def make_key(tool, rule, file_, line_):
        base = f"{tool}|{rule}|{file_}"
        return f"{base}|{line_}" if line_ is not None else base

    sup["__key"] = sup.apply(lambda r: make_key(r["tool"], r["rule"], r["file"], r["line"]), axis=1)
    df["__key"] = df.apply(lambda r: make_key(r["tool"], r["rule"], r["file"], r["line"]), axis=1)

    suppress_keys = set(sup["__key"].tolist())
    reason_map = dict(zip(sup["__key"], sup["reason"]))

    df["suppressed"] = df["__key"].isin(suppress_keys)
    df["suppress_reason"] = df["__key"].map(reason_map).fillna("")

    df.drop(columns=["__key"], inplace=True, errors="ignore")

    print(f"[ASTF] ✅ Suppression applied: {int(df['suppressed'].sum())} alerts suppressed")
    return df


# ===============================
# TRIAGE METRICS (EXPANDED)
# ===============================
def generate_metrics_df(df: pd.DataFrame, raw_total_before_dedupe: int = None) -> pd.DataFrame:
    total = len(df)
    suppressed = int(df["suppressed"].sum()) if "suppressed" in df.columns else 0
    actionable = total - suppressed

    suppression_rate = round((suppressed / total) * 100, 2) if total > 0 else 0
    actionable_rate = round((actionable / total) * 100, 2) if total > 0 else 0

    # High/Critical focus ratio
    high_crit = int(df["priority"].isin(["HIGH", "CRITICAL"]).sum()) if "priority" in df.columns else 0
    high_crit_rate = round((high_crit / total) * 100, 2) if total > 0 else 0

    # Severity distribution
    sev_counts = df["severity"].value_counts(dropna=False).to_dict() if "severity" in df.columns else {}
    pri_counts = df["priority"].value_counts(dropna=False).to_dict() if "priority" in df.columns else {}
    tool_counts = df["tool"].value_counts(dropna=False).to_dict() if "tool" in df.columns else {}

    # Dedupe rate (if caller provides raw pre-dedupe count)
    dedupe_rate = None
    if raw_total_before_dedupe is not None and raw_total_before_dedupe > 0:
        dedupe_rate = round(((raw_total_before_dedupe - total) / raw_total_before_dedupe) * 100, 2)

    # Estimated FPR (proxy) = suppressed rate
    estimated_fpr = suppression_rate

    rows = [
        ("Total Alerts (Post-Dedup)", total, "Alerts after normalization + deduplication"),
        ("Suppressed Alerts (Rule-Based)", suppressed, "Noise removed via suppress_list.csv rules"),
        ("Actionable Alerts", actionable, "Alerts remaining for developer/security action"),
        ("Suppression Rate (%)", suppression_rate, "Suppressed / Total * 100 (noise reduction)"),
        ("Actionable Rate (%)", actionable_rate, "Actionable / Total * 100"),
        ("Estimated False Positive Rate (%)", estimated_fpr, "Proxy: suppressed alerts treated as false positives"),
        ("High+Critical Priority Alerts", high_crit, "Count of alerts prioritized HIGH or CRITICAL"),
        ("High+Critical Ratio (%)", high_crit_rate, "High+Critical / Total * 100"),
    ]

    if dedupe_rate is not None:
        rows.insert(0, ("Deduplication Reduction (%)", dedupe_rate, "((Raw - PostDedup)/Raw)*100"))

    # Add compact distributions as metric rows (good for thesis tables)
    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if k in sev_counts:
            rows.append((f"Severity Count: {k}", int(sev_counts.get(k, 0)), "Distribution (severity)"))

    for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if k in pri_counts:
            rows.append((f"Priority Count: {k}", int(pri_counts.get(k, 0)), "Distribution (priority)"))

    for tool, cnt in tool_counts.items():
        rows.append((f"Tool Count: {tool}", int(cnt), "Distribution (tool source)"))

    metrics_df = pd.DataFrame(rows, columns=["Metric", "Value", "Notes"])
    return metrics_df


# ===============================
# RAW JSON -> MAIN COLUMNS ONLY
# ===============================
def _pick_columns(df: pd.DataFrame, wanted: list) -> pd.DataFrame:
    existing = [c for c in wanted if c in df.columns]
    if not existing:
        return df.head(0)
    return df[existing].copy()


def load_sast_raw_main() -> pd.DataFrame:
    path = os.path.join(RAW_DATA_DIR, "sast.json")
    if not os.path.exists(path):
        print("[WARN] sast.json not found")
        return pd.DataFrame([{"error": "sast.json missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    issues = raw.get("issues", []) if isinstance(raw, dict) else raw
    df = pd.json_normalize(issues)

    wanted = [
        "key", "rule", "severity", "type", "status",
        "component", "project", "line", "message",
        "creationDate", "updateDate"
    ]
    return _pick_columns(df, wanted)


def load_dast_raw_main() -> pd.DataFrame:
    path = os.path.join(RAW_DATA_DIR, "dast.json")
    if not os.path.exists(path):
        print("[WARN] dast.json not found")
        return pd.DataFrame([{"error": "dast.json missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    alerts = []
    if isinstance(raw, dict) and "site" in raw:
        for site in raw.get("site", []):
            alerts.extend(site.get("alerts", []))
    else:
        alerts = raw

    df = pd.json_normalize(alerts)

    wanted = [
        "pluginid", "alertRef", "alert", "riskcode",
        "confidence", "riskdesc", "desc", "solution",
        "reference", "cweid", "wascid", "sourceid"
    ]
    return _pick_columns(df, wanted)


def load_sca_raw_main() -> pd.DataFrame:
    path = os.path.join(RAW_DATA_DIR, "sca.json")
    if not os.path.exists(path):
        print("[WARN] sca.json not found")
        return pd.DataFrame([{"error": "sca.json missing"}])

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    vulns = raw.get("vulnerabilities", []) if isinstance(raw, dict) else raw
    df = pd.json_normalize(vulns)

    wanted = [
        "id", "title", "severity", "cvssScore",
        "packageName", "moduleName", "language",
        "fixedIn", "patches"
    ]
    return _pick_columns(df, wanted)


# ===============================
# SUMMARY DASHBOARD
# ===============================
def create_summary_dashboard(df: pd.DataFrame, excel_path: str):
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

    print("[ASTF] ✅ SUMMARY_DASHBOARD updated")


# ===============================
# FORMATTING
# ===============================
def apply_global_formatting(excel_path: str):
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

        # header
        for cell in ws[1]:
            cell.font = bold_font
            cell.fill = grey_fill
            cell.border = thin_border

        # borders for populated
        for row in ws.iter_rows(min_row=2):
            for cell in row:
                if cell.value is not None:
                    cell.border = thin_border

    wb.save(excel_path)
    print("[ASTF] ✅ Formatting applied")


# ===============================
# SAVE EXCEL
# ===============================
def save_excel(astf_df: pd.DataFrame,
               metrics_df: pd.DataFrame,
               suppress_df: pd.DataFrame,
               sast_df: pd.DataFrame,
               dast_df: pd.DataFrame,
               sca_df: pd.DataFrame) -> str:

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_path = os.path.join(OUTPUT_DIR, "astf_master_final.xlsx")

    with pd.ExcelWriter(output_path, engine="openpyxl") as writer:
        astf_df.to_excel(writer, sheet_name="ASTF_FINAL", index=False)
        metrics_df.to_excel(writer, sheet_name="TRIAGE_METRICS", index=False)
        suppress_df.to_excel(writer, sheet_name="SUPPRESS_LIST", index=False)

        sast_df.to_excel(writer, sheet_name="SAST_RAW_LIST", index=False)
        dast_df.to_excel(writer, sheet_name="DAST_RAW_LIST", index=False)
        sca_df.to_excel(writer, sheet_name="SCA_RAW_LIST", index=False)

    print("[ASTF] ✅ Excel created:", output_path)
    print("[ASTF] ✅ Excel absolute path:", os.path.abspath(output_path))
    return output_path


# ===============================
# MAIN
# ===============================
def main():
    print("[ASTF] Working directory:", os.getcwd())
    print("[ASTF] combined_astf.json:", os.path.abspath(INPUT_FILE))
    print("[ASTF] suppress_list.csv:", os.path.abspath(SUPPRESS_LIST_CSV))

    # Load once to capture raw count (for dedupe metric)
    df_raw = load_combined(INPUT_FILE)
    if df_raw.empty:
        print("[ASTF] ❌ No alerts detected. STOPPING.")
        return

    raw_total_before_dedupe = len(df_raw)

    df = deduplicate_alerts(df_raw)
    df = apply_priority_scoring(df)

    suppress_df = auto_generate_suppress_list(df, SUPPRESS_LIST_CSV)
    df = apply_suppression(df, SUPPRESS_LIST_CSV)

    metrics_df = generate_metrics_df(df, raw_total_before_dedupe=raw_total_before_dedupe)

    # raw views
    sast_df = load_sast_raw_main()
    dast_df = load_dast_raw_main()
    sca_df = load_sca_raw_main()

    excel_path = save_excel(df, metrics_df, suppress_df, sast_df, dast_df, sca_df)
    create_summary_dashboard(df, excel_path)
    apply_global_formatting(excel_path)

    print("\n✅ ASTF PIPELINE SUCCESSFUL")
    print("✅ Final ASTF Alerts:", len(df))


if __name__ == "__main__":
    main()

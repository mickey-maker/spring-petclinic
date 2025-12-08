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
        tool = item.get("tool") or item.get("source") or "UNKNOWN"
        issue_type = item.get("type") or item.get("issueType") or "VULNERABILITY"
        severity = item.get("severity") or item.get("risk") or "INFO"
        message = item.get("message") or item.get("title") or "No description"
        file = item.get("file") or item.get("component") or "UNKNOWN"
        rule = item.get("rule") or item.get("pluginid") or "UNKNOWN"

        normalised.append({
            "tool": tool.upper(),
            "type": issue_type.upper(),
            "severity": severity.upper(),
            "message": message,
            "file": file,
            "rule": rule,
            "data_source": "ASTF_ENGINE"
        })

    df = pd.DataFrame(normalised)
    print("[ASTF] ✅ Alerts loaded:", len(df))
    return df


# ===============================
# DEDUPLICATION
# ===============================
def deduplicate_alerts(df):
    print("[ASTF] Removing duplicate alerts...")
    before = len(df)
    df = df.drop_duplicates(subset=["tool", "type", "rule", "file"])
    after = len(df)
    print(f"[ASTF] ✅ Deduplication: {before} → {after}")
    return df


# ===============================
# PRIORITY SCORING
# ===============================
def apply_priority_scoring(df):
    print("[ASTF] Applying priority scoring...")

    SEVERITY_WEIGHT = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    TYPE_WEIGHT = {"VULNERABILITY": 5, "BUG": 3, "CODE_SMELL": 1}

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
# LOAD RAW TOOL JSON → CSV ROWS
# ===============================
def load_raw_tool_to_df(tool_name, filename):
    path = os.path.join(RAW_DATA_DIR, filename)

    if not os.path.exists(path):
        print(f"[WARN] Missing {filename}")
        return pd.DataFrame()

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    df = pd.json_normalize(raw)
    df["tool"] = tool_name
    df["data_source"] = "RAW_TOOL"

    return df


# ===============================
# GENERATE METRICS → DF ROWS
# ===============================
def generate_metrics_df(df):
    print("[ASTF] Generating metrics rows...")

    total_alerts = len(df)
    false_positive_estimate = len(df[df["priority"] == "LOW"])
    false_positive_rate = round((false_positive_estimate / total_alerts) * 100, 2)

    metrics_rows = [
        {"metric": "total_alerts", "value": total_alerts},
        {"metric": "false_positive_estimate", "value": false_positive_estimate},
        {"metric": "false_positive_rate", "value": false_positive_rate},
    ]

    return pd.DataFrame(metrics_rows)


# ===============================
# SAVE ONE MASTER CSV
# ===============================
def save_master_csv(astf_df, sast_df, dast_df, sca_df, metrics_df):
    print("[ASTF] Creating ONE MASTER FINAL CSV...")

    astf_df["section"] = "ASTF_FINAL"
    sast_df["section"] = "SAST_RAW"
    dast_df["section"] = "DAST_RAW"
    sca_df["section"] = "SCA_RAW"
    metrics_df["section"] = "TRIAGE_METRICS"

    master = pd.concat(
        [astf_df, sast_df, dast_df, sca_df, metrics_df],
        ignore_index=True,
        sort=False
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    master.to_csv(os.path.join(OUTPUT_DIR, "astf_master_final.csv"), index=False)

    print("[ASTF] ✅ astf_master_final.csv created successfully")


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

    sast_df = load_raw_tool_to_df("SAST", "sast.json")
    dast_df = load_raw_tool_to_df("DAST", "dast.json")
    sca_df = load_raw_tool_to_df("SCA", "sca.json")

    metrics_df = generate_metrics_df(df)

    save_master_csv(df, sast_df, dast_df, sca_df, metrics_df)

    print("\n✅ ASTF PIPELINE SUCCESSFUL")
    print("Final ASTF Alerts:", len(df))


if __name__ == "__main__":
    main()

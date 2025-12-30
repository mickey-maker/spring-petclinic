import json
import os
import pandas as pd

INPUT_FILE = "astf-python/combined_astf.json"
OUTPUT_DIR = "astf-python/output"

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ===============================
# LOAD COMBINED ALERTS
# ===============================
def load_combined_alerts(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing combined file: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    df = pd.DataFrame(data)
    df["severity"] = df["severity"].str.upper().fillna("INFO")
    df["type"] = df["type"].str.upper().fillna("UNKNOWN")
    df["tool"] = df["tool"].str.upper().fillna("UNKNOWN")
    df["rule"] = df["rule"].fillna("")
    df["location"] = df["location"].fillna("")
    return df


# ===============================
# DEDUPLICATION
# ===============================
def deduplicate_alerts(df):
    subset_cols = ["tool", "type", "rule", "location"]
    return df.drop_duplicates(subset=subset_cols).reset_index(drop=True)


# ===============================
# SCORING & PRIORITY
# ===============================
SEVERITY_SCORE = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
}

TYPE_SCORE = {
    "VULNERABILITY": 2,
    "CODE_SMELL": 1
}

def apply_scoring(df):
    df["sev_score"] = df["severity"].map(SEVERITY_SCORE).fillna(1)
    df["type_score"] = df["type"].map(TYPE_SCORE).fillna(1)
    df["final_score"] = df["sev_score"] * df["type_score"]

    def map_priority(score):
        if score >= 8:
            return "P1"
        elif score >= 4:
            return "P2"
        return "P3"

    df["priority"] = df["final_score"].apply(map_priority)
    return df


# ===============================
# SUPPRESSION RULES
# ===============================
def apply_suppression(df):
    df["suppressed"] = False
    df["suppress_reason"] = ""

    for idx, row in df.iterrows():
        sev = row["severity"]
        pri = row["priority"]

        # Informational alerts
        if sev == "INFO":
            df.at[idx, "suppressed"] = True
            df.at[idx, "suppress_reason"] = "Informational severity"

        # Low-priority vulnerabilities only
        elif pri == "P3" and sev == "LOW" and row["type"] == "VULNERABILITY":
            df.at[idx, "suppressed"] = True
            df.at[idx, "suppress_reason"] = "Low priority vulnerability"

    return df


# ===============================
# PRIORITY SORTING
# ===============================
def sort_by_priority(df):
    priority_rank = {"P1": 1, "P2": 2, "P3": 3}
    df["priority_rank"] = df["priority"].map(priority_rank).fillna(99)

    df = df.sort_values(
        by=["priority_rank", "final_score"],
        ascending=[True, False]
    ).reset_index(drop=True)

    return df.drop(columns=["priority_rank"])


# ===============================
# SAVE OUTPUTS
# ===============================
def save_outputs(df):
    astf_final = df[df["suppressed"] == False].copy()
    suppress_list = df[df["suppressed"] == True].copy()

    astf_final = sort_by_priority(astf_final)

    excel_path = os.path.join(OUTPUT_DIR, "astf_master_final.xlsx")

    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        astf_final.to_excel(writer, sheet_name="ASTF_FINAL", index=False)
        suppress_list.to_excel(writer, sheet_name="SUPPRESS_LIST", index=False)

    astf_final.to_csv(os.path.join(OUTPUT_DIR, "astf_final.csv"), index=False)
    suppress_list.to_csv(os.path.join(OUTPUT_DIR, "suppress_list.csv"), index=False)

    print("[ASTF] ✅ Delivered alerts:", len(astf_final))
    print("[ASTF] 🚫 Suppressed alerts:", len(suppress_list))
    print("[ASTF] 📁 Output saved to:", excel_path)


# ===============================
# MAIN PIPELINE
# ===============================
def main():
    print("[ASTF] Loading combined alerts...")
    df = load_combined_alerts(INPUT_FILE)

    print("[ASTF] Deduplicating alerts...")
    df = deduplicate_alerts(df)

    print("[ASTF] Applying scoring and prioritization...")
    df = apply_scoring(df)

    print("[ASTF] Applying suppression rules...")
    df = apply_suppression(df)

    print("[ASTF] Saving outputs...")
    save_outputs(df)

    print("[ASTF] ✅ ASTF pipeline completed successfully")


if __name__ == "__main__":
    main()

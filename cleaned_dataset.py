import os 
import json 
import pandas as pd

#====Config====
DATASET_DIR = '/Users/afiaasante/Documents/Research /Python Security Code Smell /Code/decompressed_jsons/'
CLEANED_DIR = 'cleaned_dataset'
REPORT_MISSING = "report_missing_fields.csv"
REPORT_DUP_SHA = "report_duplicate_sha.csv"
SUMMARY_CSV = "cleaned_dataset_summary.csv"

REQUIRED_FIELDS = ['content', 'repo_name', 'path', 'sha']

# ==== Load report CSVs =====
def load_report(csv_file, key_col=None):
    if os.path.exists(csv_file):
        df = pd.read_csv(csv_file)
        if key_col:
            return set(df[key_col].dropna().astype(str).tolist())
        else:
            # For missing fields, use file:entry_index
            return set((df["file"].astype(str) + ":" + df["entry_index"].astype(str)).tolist())
    return set()

# For missing fields -> use (file, entry) pairs
bad_missing = load_report(REPORT_MISSING)

# For duplicate SHA -> use sha values directly
bad_sha = load_report(REPORT_DUP_SHA, key_col="sha")

print(f"Loaded {len(bad_missing)} missing field issues")
print(f"Loaded {len(bad_sha)} duplicate SHA issues")

# === Ensure output folder exists ===
os.makedirs(CLEANED_DIR, exist_ok=True)

# === Clean files ===
seen_shas = set()
total_entries = 0
total_kept = 0
summary_records = []

for filename in os.listdir(DATASET_DIR):
    if filename.endswith('.json'):
        in_path = os.path.join(DATASET_DIR, filename)
        out_path = os.path.join(CLEANED_DIR, filename)

        cleaned_entries = []
        file_total = 0

        with open(in_path, 'r', encoding='utf-8', errors='ignore') as f:
            for idx, line in enumerate(f, start=0):
                line = line.strip()
                if not line:
                    continue
                file_total += 1
                total_entries += 1

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # skip malformed

              # Build identifier
                entry_id = f"{filename}:{idx}"

                # Filter: missing fields or invalid content
                if entry_id in bad_missing:
                    continue

                # Check required fields
                if not all(field in entry for field in REQUIRED_FIELDS):
                    continue


                # Filter: duplicate SHA
                sha = entry.get("sha")
                
                # Keep only the first occurence of each SHA
                if sha in seen_shas:
                    continue
                seen_shas.add(sha)


                # If passed all checks -> keep entry
                cleaned_entries.append(entry)


        # Write cleaned entries to new file
        with open(out_path, 'w', encoding='utf-8') as out_f:
            for entry in cleaned_entries:
                out_f.write(json.dumps(entry) + "\n")

        # Record summary per file
        summary_records.append({
            "file": filename,
            "original_entries": file_total,
            "kept_entries": len(cleaned_entries)
        })

        total_kept += len(cleaned_entries)
        print(f"Cleaned {filename}: kept {len(cleaned_entries)} of {file_total} entries")

# ==== Save summary CSV ====
summary_df = pd.DataFrame(summary_records)
summary_df.loc[len(summary_df)] = {
    "file": "TOTAL",
    "original_entries": total_entries,
    "kept_entries": total_kept
}
summary_df.to_csv(SUMMARY_CSV, index=False)

print(f"\nCleaning complete. Summary saved to {SUMMARY_CSV}")
print(f"Cleaned files saved to {CLEANED_DIR}/")
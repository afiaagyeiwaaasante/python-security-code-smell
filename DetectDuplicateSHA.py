import json
import os
import pandas as pd

DATASET_DIR = '/Users/afiaasante/Documents/Research /Python Security Code Smell /Code/decompressed_jsons/'
REPORT_FILE = 'report_duplicate_sha1.csv'

seen_sha = set()
duplicate_sha = []

def check_duplicate_sha():
    """Check dataset for duplicate SHA entries."""
    for filename in os.listdir(DATASET_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(DATASET_DIR, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                for idx, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # malformed JSON handled in another script

                    sha = entry.get('sha')
                    if not sha:
                        continue

                    if sha in seen_sha:
                        duplicate_sha.append({
                            "file": filename,
                            "entry_index": idx,
                            "sha": sha,
                            "repo_name": entry.get("repo_name", ""),
                            "path": entry.get("path", "")
                        })
                    else:
                        seen_sha.add(sha)

    # Save report
    df_dup_sha = pd.DataFrame(duplicate_sha)
    df_dup_sha.to_csv(REPORT_FILE, index=False)
    print(f"🔍 Duplicate SHA check complete. Found {len(duplicate_sha)} duplicates. Report saved as {REPORT_FILE}.")

if __name__ == "__main__":
    check_duplicate_sha()

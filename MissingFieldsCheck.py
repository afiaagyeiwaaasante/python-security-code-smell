import json
import os
import pandas as pd

DATASET_DIR = '/Users/afiaasante/Documents/Research /Python Security Code Smell /Code/decompressed_jsons/'  
REQUIRED_FIELDS = ['content', 'repo_name', 'path', 'sha']

# Store missing field issues
missing_fields = []

def check_missing_fields():
    """Check dataset for missing required fields or malformed JSON."""
    for filename in os.listdir(DATASET_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(DATASET_DIR, filename)
            with open(filepath, 'r', encoding='utf-8') as f:
                for idx, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)  # parse one JSON object per line
                    except json.JSONDecodeError:
                        missing_fields.append((filename, idx, 'Malformed JSON'))
                        continue

                    # Check required fields
                    for field in REQUIRED_FIELDS:
                        if field not in entry:
                            missing_fields.append((filename, idx, field))

    # Save to CSV
    df_missing = pd.DataFrame(missing_fields, columns=['file', 'entry_index', 'issue'])
    df_missing.to_csv("report_missing_fields.csv", index=False)
    print(f"✅ Missing fields check complete. Found {len(missing_fields)} issues. Report saved.")

if __name__ == "__main__":
    check_missing_fields()

import json
import os
import pandas as pd

DATASET_DIR = '/Users/afiaasante/Documents/Research /Python Security Code Smell /Code/decompressed_jsons/'  
REPORT_FILE = 'dataset_verification_report.csv'

REQUIRED_FIELDS = ['content', 'repo_name', 'path', 'sha']

#Track issues
missing_fields = []
invalid_content = []
duplicate_sha = set()
duplicate_path = set()
seen_sha = set()
seen_repo_path = set()

def is_python_code(code):
    """Check if the string is valid Python code."""
    if not code.strip():
        return False
    try:
        compile(code, '<string>', 'exec')
        return True
    except Exception:
        return False

#Process all NDJSON files
for filename in os.listdir(DATASET_DIR):
    if filename.endswith('.json'):
        filepath = os.path.join(DATASET_DIR, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            for idx, line in enumerate(f):
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

                # Check content validity
                content = entry.get('content', '')
                if not is_python_code(content):
                    invalid_content.append((filename, idx))

                # Check for duplicates
                sha = entry.get('sha')
                repo_path = (entry.get('repo_name'), entry.get('path'))

                if sha:
                    if sha in seen_sha:
                        duplicate_sha.add((filename, idx, sha))
                    else:
                        seen_sha.add(sha)

                if None not in repo_path:
                    if repo_path in seen_repo_path:
                        duplicate_path.add((filename, idx, repo_path))
                    else:
                        seen_repo_path.add(repo_path)

# Print summary
"""
print("\n=== Phase 1 Dataset Verification Summary ===\n")

if missing_fields:
    print(f"Missing Fields / Malformed JSON: {len(missing_fields)} entries")
    for item in missing_fields[:20]:  # show first 20 for brevity
        print(f"File: {item[0]}, Entry: {item[1]}, Field: {item[2]}")
else:
    print("All required fields are present.")

if invalid_content:
    print(f"\nInvalid / Non-Python Content: {len(invalid_content)} entries")
    for item in invalid_content[:20]:
        print(f"File: {item[0]}, Entry: {item[1]}")

if duplicate_sha:
    print(f"\nDuplicate SHA: {len(duplicate_sha)} entries")
    for item in list(duplicate_sha)[:20]:
        print(f"File: {item[0]}, Entry: {item[1]}, SHA: {item[2]}")

if duplicate_path:
    print(f"\nDuplicate repo_name + path: {len(duplicate_path)} entries")
    for item in list(duplicate_path)[:20]:
        print(f"File: {item[0]}, Entry: {item[1]}, Repo+Path: {item[2]}")

print("\nVerification complete.")
"""

# Convert duplicates to dicts for DataFrame
duplicate_sha_list = [{'file': f, 'entry': e, 'sha': s} for f, e, s in duplicate_sha]
duplicate_path_list = [{'file': f, 'entry': e, 'repo_name': r[0], 'path': r[1]} for f, e, r in duplicate_path]

# Create DataFrames
df_missing = pd.DataFrame(missing_fields)
df_invalid = pd.DataFrame(invalid_content)
df_dup_sha = pd.DataFrame(duplicate_sha_list)
df_dup_path = pd.DataFrame(duplicate_path_list)

# Save each DataFrame to a separate CSV file
df_missing.to_csv("report_missing_fields.csv", index=False)
df_invalid.to_csv("report_invalid_content.csv", index=False)
df_dup_sha.to_csv("report_duplicate_sha.csv", index=False)
df_dup_path.to_csv("report_duplicate_repo_path.csv", index=False)

print("Dataset verification complete. Reports saved as individual CSV files.")
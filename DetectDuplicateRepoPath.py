import json
import os
import pandas as pd

DATASET_DIR = '/Users/afiaasante/Documents/Research /Python Security Code Smell /Code/decompressed_jsons/'
REPORT_FILE = 'report_duplicate_repo_path.csv'

seen_repo_path = set()
duplicate_repo_path = []

def check_duplicate_repo_path():
    """Check dataset for duplicate repo_name + path entries."""
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
                        continue  # malformed JSON handled elsewhere

                    repo = entry.get('repo_name')
                    path = entry.get('path')

                    if not repo or not path:
                        continue

                    repo_path = (repo, path)

                    if repo_path in seen_repo_path:
                        duplicate_repo_path.append({
                            "file": filename,
                            "entry_index": idx,
                            "repo_name": repo,
                            "path": path,
                            "sha": entry.get("sha", "")
                        })
                    else:
                        seen_repo_path.add(repo_path)

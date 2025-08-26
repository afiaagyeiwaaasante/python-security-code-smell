import os
import json
import subprocess
import pandas as pd

# ==== Config ====
CLEANED_DIR = '/Users/afiaasante/Documents/Research /Python Security Code Smell /Code/cleaned_dataset'       # cleaned JSON files
SRCML_DIR = 'srcml_dataset'           # folder to store XML files
OUTPUT_JSON_DIR = 'json_with_srcml'   # folder for updated JSON with pointers
FAILED_CSV = 'failed_srcml_entries.csv'

os.makedirs(SRCML_DIR, exist_ok=True)
os.makedirs(OUTPUT_JSON_DIR, exist_ok=True)

LANGUAGE_EXTENSION = '.py'  # adjust to your language, e.g., '.java', '.cpp'

# List to record failed entries
failed_entries = []
parsed_files_count = 0 # Counter for parsed files

for filename in os.listdir(CLEANED_DIR):
    if filename.endswith('.json'):
        in_path = os.path.join(CLEANED_DIR, filename)
        out_path = os.path.join(OUTPUT_JSON_DIR, filename)

         # Create a folder for this JSON file in SRCML_DIR
        json_name = os.path.splitext(filename)[0]
        json_srcml_dir = os.path.join(SRCML_DIR, json_name)
        os.makedirs(json_srcml_dir, exist_ok=True)

        updated_entries = []

        with open(in_path, 'r', encoding='utf-8') as f:
            for idx, line in enumerate(f, start=0):
                entry = json.loads(line)
                code = entry.get('content', '')

                # Build a unique XML filename using sha or index
                sha = entry.get('sha', f"{idx}")
                xml_filename = f"{sha}.xml"
                xml_path = os.path.join(SRCML_DIR, xml_filename)

                # Temporary source file
                temp_file = f'temp_code{idx}{LANGUAGE_EXTENSION}'
                with open(temp_file, 'w', encoding='utf-8') as tmp:
                    tmp.write(code)

                # Run srcML
                try:
                    subprocess.run(
                        ['srcml', temp_file, '-o', xml_path],
                        check=True,
                        capture_output=True,
                        text=True
                    )
                    # Save pointer to XML in JSON
                    entry['srcml_file'] = xml_path
                except subprocess.CalledProcessError as e:
                    entry['srcml_file'] = None
                    failed_entries.append({
                        "file": filename,
                        "entry_index": idx,
                        "sha": sha,
                        "reason": e.stderr.strip() if e.stderr else "Unknown srcML error"
                    })

                updated_entries.append(entry)
                os.remove(temp_file)

        #Count this file if at least one entry succeeded
        if any(entry['srcml_file'] for entry in updated_entries):
            parsed_files_count += 1
            print(f"Total parsed files so far: {parsed_files_count}")   

        # Write updated JSON with srcML pointers
        with open(out_path, 'w', encoding='utf-8') as out_f:
            for entry in updated_entries:
                out_f.write(json.dumps(entry) + "\n")

        print(f"Processed {filename}: srcML files saved, JSON updated")

# ==== Save failed entries to CSV ====
df_failed = pd.DataFrame(failed_entries)
df_failed.to_csv(FAILED_CSV, index=False)

print(f"\nTotal failed entries: {len(failed_entries)}")
print(f"Failed entries recorded in {FAILED_CSV}")
print(f"Total successfully parsed files: {parsed_files_count}") 


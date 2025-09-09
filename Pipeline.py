import os
import csv
import subprocess
import shutil
from glob import glob

DATASET_FILE = "dataset.csv"
OUTPUT_FILE = "violations.csv"
FAILED_FILE = "failed_files.csv"
QUERY_FOLDER = "srcQL_Queries"
TEMP_DIR = "temp_repos"

# Ensure temp directory exists
os.makedirs(TEMP_DIR, exist_ok=True)

# Get all .ql query files
ql_files = glob(os.path.join(QUERY_FOLDER, "*.ql"))

# Read dataset and organize files by repo
repo_files = {}
with open(DATASET_FILE) as f:
    reader = csv.reader(f)
    for repo, path, *_ in reader:
        repo_files.setdefault(repo, []).append(path)

# Open output CSVs
with open(OUTPUT_FILE, "w", newline="") as out_csv, \
     open(FAILED_FILE, "w", newline="") as fail_csv:

    out_writer = csv.writer(out_csv)
    fail_writer = csv.writer(fail_csv)

    out_writer.writerow(["repo", "file_path", "violation", "line"])
    fail_writer.writerow(["repo", "file_path", "reason"])

    for repo, files in repo_files.items():
        print(f"Processing repo: {repo}")

        # Prepare local path for the repo
        repo_name = repo.replace("/", "_")
        local_repo_path = os.path.join(TEMP_DIR, repo_name)

        # Clone repo shallowly
        if os.path.exists(local_repo_path):
            shutil.rmtree(local_repo_path)
        clone_cmd = ["git", "clone", "--depth", "1", f"https://github.com/{repo}.git", local_repo_path]
        try:
            subprocess.run(clone_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            print(f"Failed to clone repo: {repo}")
            for f in files:
                fail_writer.writerow([repo, f, "Failed to clone repo"])
            continue

        # Process each Python file
        for file_path in files:
            abs_path = os.path.join(local_repo_path, file_path)
            if not os.path.exists(abs_path):
                print(f"Missing file: {file_path} in {repo}")
                fail_writer.writerow([repo, file_path, "File not found in repo"])
                continue

            # Parse with srcML
            xml_file = abs_path + ".xml"
            try:
                subprocess.run(["srcml", abs_path, "-o", xml_file], check=True)

                # Run each srcQL query
                for ql in ql_files:
                    result = subprocess.run(
                        ["srcql-cli", ql, xml_file],
                        capture_output=True, text=True
                    )
                    if result.stdout:
                        for line in result.stdout.strip().split("\n"):
                            out_writer.writerow([repo, file_path, line.split(":")[0], ":".join(line.split(":")[1:])])

            except subprocess.CalledProcessError as e:
                print(f"srcML or srcQL failed for {file_path} in {repo}: {e}")
                fail_writer.writerow([repo, file_path, "srcML/srcQL error"])

            finally:
                # Delete Python and XML files
                if os.path.exists(abs_path):
                    os.remove(abs_path)
                if os.path.exists(xml_file):
                    os.remove(xml_file)

        # Delete cloned repo folder
        if os.path.exists(local_repo_path):
            shutil.rmtree(local_repo_path)

print("Processing complete.")

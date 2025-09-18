import subprocess
import os
from sklearn.metrics import precision_score, recall_score

# Paths
SRCQL_QUERY = "../srcQL_Queries/ClearTextTrans.ql"
TEST_DIR = "../testsuite/CWE-319-CleartextTransmission"

def run_query_on_file(file_path):
    """Run srcQL query on a single file and return True if violation detected."""
    result = subprocess.run(
        ["srcml", file_path, f"--srcql=@{SRCQL_QUERY}"],
        capture_output=True,
        text=True
    )
    return bool(result.stdout.strip())  # if query returned matches

def collect_labels():
    """Prepare ground truth labels and predictions."""
    y_true, y_pred, files = [], [], []

    for label, folder in [(1, "positives"), (0, "negatives")]:
        folder_path = os.path.join(TEST_DIR, folder)
        for fname in os.listdir(folder_path):
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(folder_path, fname)

            # Run srcQL
            detected = run_query_on_file(fpath)

            # Append results
            y_true.append(label)
            y_pred.append(1 if detected else 0)
            files.append((fname, label, detected))

    return y_true, y_pred, files

if __name__ == "__main__":
    y_true, y_pred, files = collect_labels()

    # Metrics
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)

    # Print results
    print("---- Evaluation Results ----")
    print(f"Precision: {precision:.2f}")
    print(f"Recall: {recall:.2f}")
    print("\nFile-level results:")
    for fname, label, detected in files:
        print(f"{fname} | True={label} | Pred={detected}")

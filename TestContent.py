import requests
import base64

owner = "cdelsey"
repo = "cannibals-and-missionaries"
commit = "5403061fd93062e41b9a6a54beb370395bc556fb"
path = "solve.py"
headers = {"Accept": "application/vnd.github.v3+json"}

# Step 1: Get tree
tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{commit}?recursive=1"
r = requests.get(tree_url, headers=headers)
if r.status_code == 200:
    tree = r.json()["tree"]
    blob_sha = None
    for item in tree:
        if item["path"] == path:
            blob_sha = item["sha"]
            break

    if blob_sha:
        # Step 2: Get blob content
        blob_url = f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{blob_sha}"
        r2 = requests.get(blob_url, headers=headers)
        if r2.status_code == 200:
            content = base64.b64decode(r2.json()['content']).decode('utf-8')
            with open("solve.py", "w") as f:
                f.write(content)
        else:
            print("Failed to download blob:", r2.status_code)
    else:
        print("File not found in commit tree")
else:
    print("Failed to get commit tree:", r.status_code)


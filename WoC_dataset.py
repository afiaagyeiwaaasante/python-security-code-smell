from woc import remote

# Connect to WoC remote interface
db = remote.connect()

# Example:get all Python files
for f in db.file_name("*.py"):
    print(f)
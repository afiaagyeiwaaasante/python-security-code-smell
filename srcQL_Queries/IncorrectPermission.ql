/*
V0732 - CWE-732: Incorrect Permission Assignment (files/directories)
The software assigns incorrect or overly permissive rights to a resource, 
allowing unintended actors to read, modify, or execute it.
 */

//V0732 - Detect os.chmod() with insecure permission
FIND $F($A, $M)
WHERE MATCH($F, "os\\.chmod")
  AND MATCH($M, "0o777|0o666|stat\\.S_IRWXU|stat\\.S_IRWXG|stat\\.S_IRWXO")


// V0732 - Detect open() with overwrite in sensitive files
FIND $F($A, $M)
WHERE MATCH($F, "open")
  AND MATCH($M, "\"w\"|\"w\\+\"|\"a\"")

//V0732 - Detect unsafe temporary file creation
FIND $F($A)
WHERE MATCH($F, "tempfile\\.mktemp")

//Detect subprocess with insecure unmask
FIND $F($A)
WHERE MATCH($F, "os\\.umask")
  AND MATCH($A, "0")

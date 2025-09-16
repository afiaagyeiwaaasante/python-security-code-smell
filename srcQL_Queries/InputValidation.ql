/*
V020 - CWE -20 - Improper Input Validation
The software does not validate or incorrectly validates input, 
allowing unexpected values to influence execution.
*/

//V020 - Detect direct use of input()
FIND $F()
WHERE MATCH($F, "input")

//V020 - Detect usage of sys.argv
FIND $S
WHERE MATCH($S, "sys\\.argv")

//V020 - Detect usage of environment variables
FIND $S
WHERE MATCH($S, "os\\.environ")

// V020 - Detect unvalidated web request parameters
FIND $S
WHERE MATCH($S, "request\\.args|request\\.form|request\\.GET|request\\.POST")

//V020 - Detect file operations using direct input
FIND $F($A)
WHERE MATCH($F, "open")
  AND MATCH($A, "input|sys\\.argv|request")


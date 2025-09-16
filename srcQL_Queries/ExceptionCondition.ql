/*
V0703 - CWE-703: Improper Exception Handling 
Improper exception handling occurs when a program either suppresses 
exceptions, handles them incorrectly, or exposes sensitive information 
through error messages.
*/

//V0703 - Detect bare except: blocks
FIND $E
WHERE MATCH($E, "except\\s*:")

//V0703 - Detect broad exception handling
FIND $E
WHERE MATCH($E, "except\\s+Exception")

//VO703 - Detect exception blocks that log or print sensitive information
FIND $E($V)
WHERE MATCH($E, "print|logging\\.error|logging\\.exception|logger\\.error|logger\\.exception")
  AND MATCH($V, "(?i)(password|token|secret|key|ssn|credit)")

//V0703 - Detect empty exception handlers (no operation / pass)
FIND $E
WHERE MATCH($E, "except.*:\\s*pass")

//V0703 - Detect exception handling that suppresses multiple types 
FIND $E
WHERE MATCH($E, "except\\s*\\(.*\\)\\s*:")


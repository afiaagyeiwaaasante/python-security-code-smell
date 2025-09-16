/*
V0200 - CWE - 200: Exposure of Sensitive Information to an Unauthorized Actor.
The application exposes sensitive information to an actor who is not explicitly 
authorized to have access to it.
*/

// V0200 - Detect printing of sensitive variables
FIND $F($V)
WHERE MATCH($F, "print")
  AND MATCH($V, "(?i)(password|passwd|pwd|secret|token|key|ssn|credit|card)")


// V0200 - Detect logging of sensitive variables
FIND $F($V)
WHERE MATCH($F, "logging\\.info|logging\\.debug|logging\\.error|logger\\.info|logger\\.debug|logger\\.error")
  AND MATCH($V, "(?i)(password|token|secret|key|ssn|credit|card)")


// V0200 - Detect exposure in HTTP responses 
FIND $F($V)
WHERE MATCH($F, "return|Response")
  AND MATCH($V, "(?i)(password|token|secret|key|ssn|credit|card)")


//V0200 - Detect writing sensitive variables to files
FIND $F($V)
WHERE MATCH($F, "open|write|writelines")
  AND MATCH($V, "(?i)(password|token|secret|key|ssn|credit|card)")


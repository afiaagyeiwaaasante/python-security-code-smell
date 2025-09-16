/*
V0798 - CWE-798: Use of Hard-coded credentials
The software contains hard-coded credentials, such as a password, 
API key, or cryptographic key, which cannot be changed without modifying 
the source code.
*/

// V0798 - CWE-798: Hardcoded credentials in variable declarations
FIND $D = "$T" 
WHERE  MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth|apikey)[^.!?]*[.!?]?")


// V0798 - CWE-798: Hardcoded credentials in function parameter names
FIND $T($N)
WHERE MATCH ($N,"[^.!?]*(passwd|password|pwd|key|secret|token|auth|apikey)[^.!?]*[.!?]?")

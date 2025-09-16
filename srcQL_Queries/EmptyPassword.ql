/*
V0258 - CWE-258: Empty Password in Configuration 
The software uses an empty password in a 
security context, allowing unintended access.
*/

//V0258 - Detect empty password variable assignments
FIND $D=$N
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 
AND MATCH ($N, "''")

// V0258 - CWE-258: Empty Password in Configuration for  string ""
FIND $D=$N
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 
AND MATCH ($N, "\"\"") 

// V0258 - CWE-258: Empty Password in Argument of Function Calls
FIND $N($D="")
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 

// V0258 - CWE-258: Empty Password in Argument of Function Calls
FIND $N($D='')
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 

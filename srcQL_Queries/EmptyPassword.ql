// V0258 - CWE-258: Empty Password in Configuration for char ''
FIND $D=$N
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 
UNION
FIND $N =''

// V0258 - CWE-258: Empty Password in Configuration for  string ""
FIND $D=$N
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 
UNION
FIND $N =""

// V0258 - CWE-258: Empty Password in Argument of Function Calls
FIND $N($D="")
WHERE MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") 

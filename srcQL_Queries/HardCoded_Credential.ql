// V0798 - CWE-798: Hardcoded credentials in variable declarations
FIND $D = "$T"
WHERE  MATCH ($D,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?") --output-src


// V0798 - CWE-798: Hardcoded credentials in function parameter names
FIND $T($N)
WHERE MATCH ($N,"[^.!?]*(passwd|password|pwd|key|secret|token|auth)[^.!?]*[.!?]?")'

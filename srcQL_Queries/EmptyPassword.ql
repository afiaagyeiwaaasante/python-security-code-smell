// V0258 - CWE-258: Empty Password in Configuration
FIND src:assign $A;
WHERE $A CONTAINS src:name MATCHES "password|passwd|pwd|secret|key|token|auth"
  AND $A CONTAINS src:literal MATCHES "^\"\"$|^''$"
RETURN $A;

// V0258 - CWE-258: Empty Password in Function Calls
FIND //src:call/src:argument $ARG
WHERE $ARG CONTAINS src:literal MATCHES "^\"\"$|^''$"
  AND $ARG.get_name() MATCHES "password|passwd|pwd|secret|key|token|auth"
RETURN $ARG;

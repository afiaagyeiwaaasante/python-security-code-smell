/*
 V0215 - CWE-215: Debug Info Exposure
 The software contain code for diagnostic or debugging purposes 
 that exposes sensitive information to an attacker.
 */

 //V0215 - Detect debug flag set to True
FIND $A
WHERE MATCH($A, "(?i)DEBUG\\s*=\\s*True")


//V0215 - Detect logging in debug mode
FIND $F($A)
WHERE MATCH($F, "logging\\.debug|logger\\.debug")


//V0215 - Detect print statement leaking variables 
FIND $F($A)
WHERE MATCH($F, "print")
  AND MATCH($A, "(?i)(password|token|secret|key|ssn|credit)")


//V0215 - Detect Stack trace exposure 
FIND $F($A)
WHERE MATCH($F, "traceback\\.print_exc|traceback\\.format_exc|sys\\.excepthook")


//V0215 - Detect debug modules 
FIND $I
WHERE MATCH($I, "(?i)import\\s+pdb|from\\s+pdb")


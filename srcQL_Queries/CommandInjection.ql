/*
V0078 - CWE-78: OS Command Injection
OS Command Injection occurs when an application constructs an 
OS command from external (untrusted) input and executes it. 
Detect patterns such as 
- direct calls to command-execution APIs
- use of shell=True
- passing user-controlled variables/input/untrusted values to command APIs
- building command strings via concatenation/formatting/f-strings with embedded variables
*/

// V0078 - Find direct uses of command-execution APIs 
FIND $F($A)
WHERE MATCH($F, "^(os\\.system|os\\.popen|subprocess\\.Popen|subprocess\\.call|subprocess\\.run|commands\\.getoutput|sh\\.Command)$")


// V0078 - Find calls to subprocess-like functions where shell=True 
FIND $F($A)
WHERE MATCH($F, "^(subprocess\\.run|subprocess\\.Popen|subprocess\\.call)$")
  AND MATCH($A, "shell\\s*=\\s*True")


// V0078 - Find cases where likely-untrusted variables are passed to command APIs
FIND $F($V)
WHERE MATCH($F, "^(os\\.system|os\\.popen|subprocess\\.Popen|subprocess\\.call|subprocess\\.run)$")
  AND MATCH($V, "(?i)^(cmd|command|command_str|shell_cmd|user_cmd|input|args|commandline)$")


// V0078 - Find input() used directly
FIND $F(input($P))
WHERE MATCH($F, "^(os\\.system|os\\.popen|subprocess\\.Popen|subprocess\\.call|subprocess\\.run)$")


//V0078 - Find command strings built via concatenation for f-strings or .format detection
FIND $S
WHERE MATCH($S, "(?s)(f\\\".*\\{.+\\}.*\\\"|\\{\\}.format\\(|\\.format\\())")


// V0078 - Find command strings built via concatenation for concatenation with a variable-like token
FIND $E
WHERE MATCH($E, "\\+")
  AND MATCH($E, "(?i)(cmd|command|input|user_cmd|shell_cmd)")


//V0078 - Find sensitive and untrustred variable passed into exec API OR shell=True
FIND $F($V)
WHERE MATCH($F, "^(os\\.system|os\\.popen|subprocess\\.Popen|subprocess\\.call|subprocess\\.run)$")
  AND ( MATCH($V, "(?i)^(cmd|command|command_str|shell_cmd|user_cmd|input|args|commandline)$"))
        OR MATCH($V, "(?s)f\\\".*\\{.+\\}.*\\\"|\\.format\\(") )

//V0078 - Detect sh library usage or shell wrappers
FIND $F($A)
WHERE MATCH($F, "^(sh\\.|sh\\.|commands\\.|popen2\\.)")

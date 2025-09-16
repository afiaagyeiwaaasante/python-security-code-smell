/*
V0094 - CWE-94: Improper Control of Code Generation (Code Injection)
The software constructs all or part of a code segment using externally-influenced 
input from an upstream component, but it does not neutralize or improperly 
neutralizes special elements that could modify the syntax or behavior of the intended 
code.
*/

// V0094 - Find direct use of dangerous functions
FIND $F($S)
WHERE MATCH ($F, "eval|exec|compile|pickle.loads|yaml.loads")

// V0094 - Find dangerous functions invoked with variables 
FIND $F($V)
WHERE MATCH($F, "eval|exec|compile|pickle.loads|yaml.load")
  AND MATCH($V, "[a-zA-Z0-9]+")

//V0094 - Find function definitions that wrap dangerous calls
FIND $F($A)
WHERE MATCH($A, "eval|exec|compile|pickle.loads|yaml.load")

//V0094 - Sensitive variable names passed to dangerous functions
FIND $F($V)
WHERE MATCH($F, "eval|exec|compile")
  AND MATCH($V, "(?i)(password|token|secret|query|input|cmd)")

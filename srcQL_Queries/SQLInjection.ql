/*
V0089 - CWE 89 - SQL Injection
The software constructs all or part of an SQL command using 
externally-influenced input from an upstream component, 
but it does not neutralize or incorrectly neutralizes special 
elements that could modify the intended SQL command.
*/

//V0089 - Detect raw SQL string literals
FIND $S
WHERE MATCH($S, "(?i)\\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\\b")

//V0089 - Detect execute calls with SQL argument 
FIND $F($Q)
WHERE MATCH($F, "\\b(execute|executemany)\\b")
  AND MATCH($Q, "(?i)(SELECT|INSERT INTO|UPDATE|DELETE FROM)")

//V0089 - Detect SQL constructed via concatenation / formatting
FIND $F($A)
WHERE MATCH($F, "\\b(execute|executemany)\\b")
  AND MATCH($A, "(\\+|%\\s*\\(|\\.format\\(|f\\\"|f\\')))")

//Check for the injection for +, f-string, (make sure that the code is written clearly)
//Check if the execution is a resultant of the input code not some injection
//Check on program slicing 
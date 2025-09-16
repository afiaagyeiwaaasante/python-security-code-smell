/*
// V0377 - CWE-377:  Insecure Temporary File Creation
The software uses a temporary file in a way that allows 
sensitive information to be disclosed or modified by an 
unauthorized user.
*/

// V0377 - Detect use of tempfile.mktemp()
FIND $F($A)
WHERE MATCH($F, "tempfile\\.mktemp")

// V0377 - Detect direct creation of files under /tmp
FIND $F($A)
WHERE MATCH($F, "open")
  AND MATCH($A, "\"/tmp/.*\"")

//V0377 - Detect use of NamedTemporaryFile without secure flags
FIND $F($A)
WHERE MATCH($F, "tempfile\\.NamedTemporaryFile")
  AND MATCH($A, "delete\\s*=\\s*False")



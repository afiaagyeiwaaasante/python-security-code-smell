/*
V0599 - CWE-599: Missing Validation of Certificate Hostname
The software establishes an SSL/TLS connection but fails to 
properly validate the hostname in the certificate. 
This means that even if the certificate is valid and signed, 
it could belong to a different host, opening the door to 
man-in-the-middle (MITM) attacks.
*/


// V0599 - Insecure verfiy=False
FIND $S
WHERE MATCH($S, "(?i)verify\s*=\s*False")


// V0599 - Using _create_unverified_context()
FIND $S
WHERE MATCH($S, "(?i)_create_unverified_context")

//V0599 - Disabling warnings 
FIND $S
WHERE MATCH($S, "(?i)disable_warnings")

//V0599 - Hostname Validation Disabled
FIND $S
WHERE MATCH($S, "(?i)check_hostname\s*=\s*False")

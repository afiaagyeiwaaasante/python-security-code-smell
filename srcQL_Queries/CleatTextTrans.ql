/*
  CWE-319 : Cleartext Transmission of Sensitive Information 
  The product transmits sensitive or security-critical data in cleartext 
  in a communication channel that can be sniffed by unauthorized actors.
*/

// V0319 - CWE-319: Cleartext Transmission of Sensitive Information (HTTP, FTP, SMTP, Telnet)
FIND $S 
WHERE MATCH ($S, "^(?i)(http://|ftp://|smtp://|telnet://)")

// V0319 - API parameters with insecure URLS 
FIND $F($S)
WHERE MATCH ($S, "^(?i)(http://|ftp://|smtp://|telnet://)")

// V0319 - Insecure network constructors (no encryption)
FIND $F($S)
WHERE MATCH ($F, "HTTPConnection|SMTP|FTP")
        AND NOT ($F, "HTTPSConnection|SMTP_SSL|FTP_TLS")

// V0319 - Sensitive variables passed into insecure methods
FIND $F($S)
WHERE MATCH ($S, "(?i)(password|passwd|token|secret|ssn|key)")
  AND MATCH ($F, "HTTPConnection|SMTP|FTP|send|login")



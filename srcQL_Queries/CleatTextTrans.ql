// V0319 - CWE-319: Cleartext Transmission of Sensitive Information (HTTP)
FIND //src:call/src:name[
        .='requests.get' OR .='requests.post' OR .='requests.request'
     ] CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES "^http://"
RETURN $C;

// V0319 - CWE-319: Cleartext Transmission of Sensitive Information (FTP)
FIND //src:call/src:name[.='ftplib.FTP']
RETURN $C;

// V0319 - CWE-319: Cleartext Transmission of Sensitive Information (Telnet)
FIND //src:call/src:name[.='telnetlib.Telnet']
RETURN $C;

// V0319 - CWE-319: Cleartext Transmission of Sensitive Information (socket)
FIND //src:call/src:name[.='socket.connect'] CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES ".*:80$|.*:21$"
RETURN $C;

// V0319 - CWE-319: Cleartext Transmission of Sensitive Information (sensitive variables)
FIND //src:call/src:name[
        .='requests.get' OR .='requests.post' OR .='requests.request' OR
        .='socket.connect' OR .='ftplib.FTP' OR .='telnetlib.Telnet'
     ] CONTAINS src:argument/src:name
WHERE src:argument/src:name MATCHES "password|token|apikey|auth"
RETURN $C;

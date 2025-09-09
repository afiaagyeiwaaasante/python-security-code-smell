// V0599 - CWE-599: Missing Validation of Certificate Hostname (unverified context)
FIND //src:call/src:name[.='ssl._create_unverified_context']
RETURN $C;

// V0599 - CWE-599: Missing Validation of Certificate Hostname (check_hostname=False)
FIND //src:call/src:name CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES "check_hostname.*False"
RETURN $C;

// V0599 - CWE-599: Missing Validation of Certificate Hostname (SSLContext)
FIND //src:call/src:name[.='ssl.SSLContext' OR .='ssl.create_default_context']
CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES "check_hostname.*False"
RETURN $C;

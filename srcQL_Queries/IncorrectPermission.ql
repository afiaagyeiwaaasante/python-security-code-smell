// V0732 - CWE-732: Incorrect Permission Assignment (files/directories)
FIND //src:call/src:name[
        .='os.chmod' OR .='os.mkdir' OR .='os.makedirs'
     ] CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES "0o777|0o666"
RETURN $C;

// V0732 - CWE-732: Incorrect Permission Assignment (critical resource files)
FIND //src:call/src:name[
        .='open' OR .='tempfile.NamedTemporaryFile'
     ] CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES ".*\\.(pem|key|conf|credential|secret)$"
   AND $C CONTAINS src:argument/src:literal MATCHES "0o777|0o666"
RETURN $C;

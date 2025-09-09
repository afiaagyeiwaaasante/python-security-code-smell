// V0377 - CWE-377: Insecure Temporary File Creation (mktemp)
FIND //src:call/src:name[.='tempfile.mktemp']
RETURN $C;

// V0377 - CWE-377: Insecure Temporary File Creation (manual /tmp/ path)
FIND //src:call/src:name[.='open'] CONTAINS src:argument/src:literal
WHERE src:argument/src:literal MATCHES "/tmp/.*"
RETURN $C;

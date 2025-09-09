// V0089 - CWE-89: SQL Injection via concatenation
FIND src:call $C;
WHERE $C.get_target().get_name() MATCHES "execute|executemany"
  AND $C CONTAINS src:binary_op[. = '+']
RETURN $C;

// V0089 - CWE-89: SQL Injection via f-string
FIND src:call $C;
WHERE $C.get_target().get_name() MATCHES "execute|executemany"
  AND $C CONTAINS src:fstring
RETURN $C;

// V0089 - CWE-89: SQL Injection via str.format()
FIND src:call $C;
WHERE $C.get_target().get_name() MATCHES "execute|executemany"
  AND $C CONTAINS src:call[src:name='format']
RETURN $C;

// V0089 - CWE-89: SQL Injection via % operator
FIND src:call $C;
WHERE $C.get_target().get_name() MATCHES "execute|executemany"
  AND $C CONTAINS src:binary_op[. = '%']
RETURN $C;

// V0089 - CWE-89: SQL Injection via variable argument
FIND src:call $C;
WHERE $C.get_target().get_name() MATCHES "execute|executemany"
  AND $C CONTAINS src:argument[src:name]
RETURN $C;
